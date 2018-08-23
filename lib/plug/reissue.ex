defmodule Plug.Oz.Reissue do
  @moduledoc false

  @behaviour Plug

  alias Plug.Conn

  def init(opts) do
    Map.new(opts)
  end

  def call(conn, options) when is_list(options), do: call(conn, Map.new(options))
  def call(conn, %{encryption_password: password} = options) when is_binary(password) do
    options = %{ticket: options |> Map.get(:payload, %{}) |> Map.take([:issue_to, :scope])}
              |> Deep.merge(options)
              |> Map.merge(%{check_expiration: false})

    conn
    |> Hawk.Request.new()
    |> Oz.Server.authenticate(password, options)
    |> validate_app(options)
    |> case do
       {:error, {status, msg}}         ->
        conn
        |> Conn.resp(status, msg)
        |> Conn.halt()

       {:error, {status, msg, {header, value}}} ->
        conn
        |> Conn.put_resp_header(header, value)
        |> Conn.resp(status, msg)
        |> Conn.halt()

       {:ok, %{ticket: ticket}} ->
        conn
        |> Conn.put_resp_content_type("application/json")
        |> Conn.resp(200, Jason.encode!(ticket))
    end
  end

  defp validate_app({:error, reason}, _options), do: {:error, reason}
  defp validate_app({:ok, %{ticket: %{app: app}}} = ok, %{load_app_fn: load_app_fn} = options) when is_function(load_app_fn) do
    validate_app(ok, load_app_fn.(app), options)
  end
  defp validate_app({:ok, %{ticket: _ticket}}, app, %{payload: %{issue_to: issue_to}}) when is_binary(issue_to) and not :erlang.is_map_key(:delegate, app) do
    {:error, {401, "Application has no delegation rights", Hawk.Header.error("Application has no delegation rights")}}
  end
  defp validate_app({:ok, %{ticket: %{algorithm: _, id: _, key: _, scope: _, grant: grant} = ticket} = result}, %{algorithm: _, id: _, key: _}, %{encryption_password: password, load_grant_fn: load_grant_fn} = options) when is_function(load_grant_fn) do
    grant
    |> load_grant_fn.()
    |> validate_ticket_grant(ticket, Hawk.Now.msec())
    |> case do
         {:error, reason} -> {:error, reason}

         %{grant: grant}  ->
           {:ok, %{result | ticket: Oz.Ticket.reissue(ticket, grant, password, Map.merge(options[:ticket], Map.take(grant, [:ext])))}}
       end
  end
  defp validate_app({:ok, %{ticket: %{algorithm: _, id: _, key: _, scope: _} = ticket} = result}, %{algorithm: _, id: _, key: _}, options) do
    {:ok, %{result | ticket: Oz.Ticket.reissue(ticket, options[:encryption_password], options[:ticket])}}
  end
  defp validate_app(_ticket, _app, _options), do: {:error, {401, "Invalid application", Hawk.Header.error("Invalid application")}}

  defp validate_ticket_grant(%{grant: %{app: app, user: user, exp: exp}}, %{app: app, dlg: app, user: user}, now) when exp <= now, do: {:error, {401, "Invalid grant", Hawk.Header.error("Invalid grant")}}
  defp validate_ticket_grant(grant = %{grant: %{app: app, user: user}}, %{app: app, user: user}, _now), do: grant
  defp validate_ticket_grant(_grant, _ticket, _now), do: {:error, {401, "Invalid grant", Hawk.Header.error("Invalid grant")}}
end
