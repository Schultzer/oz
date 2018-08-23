defmodule Oz.Client do
  @moduledoc """
  Documentation for Oz.
  """

  defstruct [app_ticket: nil,
             result: nil,
             credentials: nil,
             endpoints: %{app: "/oz/app", reissue: "/oz/reissue"},
             ticket: nil,
             uri: "http://example.com"]

  @type t :: %__MODULE__{}

  @doc false
  @spec new(binary(), map(), keyword() | map()) :: t()
  def new(uri, credentials, options \\ [])
  def new(uri, %{id: _, algorithm: _, key: _} = credentials, options) when is_binary(uri) do
    struct(%{@struct | uri: uri, credentials: credentials}, options)
  end

  @doc """
  Generate header
  """
  @spec header(binary() | URI.t(), Hawk.method(), map(), keyword() | map()) :: %{artifacts: map(), header: binary()}
  def header(uri, method, ticket, options \\ %{})
  def header(uri, method, ticket, options) when is_list(options), do: header(uri, method, ticket, Map.new(options))
  def header(uri, method, ticket, options) do
    Hawk.Client.header(uri, method, ticket, Map.merge(options, Map.take(ticket, [:app, :dlg])))
  end

  def app(client, path, options \\ %{})
  def app({:error, reason}, _path, _options), do: {:error, reason}
  def app(client, path, options) when is_list(options), do: app(client, path, Map.new(options))
  def app(%__MODULE__{app_ticket: nil} = client, path, options) do
    client
    |> _request_app_ticket()
    |> app(path, options)
  end
  def app(%__MODULE__{} = client, path, options) do
    resp = request(client, path, options)
    %{client | app_ticket: resp.ticket, ticket: resp.ticket, result: resp.result}
  end

  defp _request_app_ticket(%__MODULE__{credentials: credentials, endpoints: %{app: app}, uri: uri} = client) do
    url = uri <> app
    %{header: header} = header(url, :post, credentials)
    case :httpc.request(:post, {[url], [{'authorization', [header]}], [], []}, [], []) do
      {:ok, {{_, 200, _}, _headers, body}} ->
        app_ticket = Jason.decode!(body, keys: &mixed_keys/1)
        %{client | app_ticket: app_ticket, ticket: app_ticket}

      {:ok, {{_, _status, _}, _headers, _body}} -> {:error, {500, "Client registration failed with unexpected response"}}

      _                                         -> {:error, {500, "Client registration failed with unexpected response"}}
        # Hawk.InternalServerError.error("Client registration failed with unexpected response", %{status: status, payload: Jason.decode!(body, keys: &mixed_keys/1)})
    end
  end

  @spec reissue(t()) :: t() | no_return()
  def reissue(%__MODULE__{endpoints: %{reissue: reissue}, uri: uri, ticket: ticket} = client) do
    case do_request(:post, uri <> reissue, ticket, []) do
      %{status: 200, result: reissue} -> %{client | ticket: reissue}

      %{result: result}               -> {:error, {500, result}}
    end
  end

  @doc """
  """
  @spec request(t(), binary(), map() | keyword()) :: t()
  def request(client, path, options \\ %{})
  def request(%__MODULE__{app_ticket: nil}, _path, _options), do: {:error, {500, "Missing app_ticket"}}
  def request(%__MODULE__{uri: uri, ticket: ticket} = client, path, options) do
    method  = options[:method] || :get
    url = uri <> path
    payload = options[:payload] || []

    case do_request(method, url, ticket, payload) do
      %{status: status, result: result} when status == 401 or :erlang.is_map_key("expired", result) ->
        client = reissue(client)
        %{client | result: do_request(method, url, client.ticket, payload).result}

      %{result: result} -> %{client | result: result}
    end
  end

  def do_request(method, url, ticket, payload \\ [])
  def do_request(:post, url, ticket, []) do
    %{header: header, artifacts: artifacts} = header(url, :post, ticket)
    :post
    |> :httpc.request({[url], [{'authorization', [header]}], [], []}, [], [])
    |> handle_resp(ticket, artifacts)
  end
  def do_request(:post, url, ticket, payload) do
    %{header: header, artifacts: artifacts} = header(url, :post, ticket)
    :post
    |> :httpc.request({[url], [{'authorization', [header]}], 'application/json', [Jason.encode!(payload)]}, [], [])
    |> handle_resp(ticket, artifacts)
  end
  def do_request(method, url, ticket, []) when method in [:get, :delete, :put] do
    %{header: header, artifacts: artifacts} = header(url, method, ticket)
    method
    |> :httpc.request({[url], [{'authorization', [header]}]}, [], [])
    |> handle_resp(ticket, artifacts)
  end
  def do_request(method, url, ticket, payload) when method in [:get, :delete, :put] do
    %{header: header, artifacts: artifacts} = header(url, method, ticket)
    method
    |> :httpc.request({[url], [{'authorization', [header]}], 'application/json', [Jason.encode!(payload)]}, [], [])
    |> handle_resp(ticket, artifacts)
  end

  def handle_resp({:ok, {{_, status, _}, headers, body}}, ticket, artifacts) do
    Hawk.Client.authenticate(headers, ticket, artifacts)
    %{status: status, result: Jason.decode!(body, keys: &mixed_keys/1)}
  end

  defp mixed_keys(key) do
    try do
      String.to_existing_atom(key)
    rescue
      ArgumentError -> key
    end
  end
end
