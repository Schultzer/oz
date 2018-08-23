defmodule Plug.Oz.App do
  @moduledoc false

  @behaviour Plug

  alias Plug.Conn

  def init(opts) do
    Map.new(opts)
  end

  def call(conn, options) when is_list(options), do: call(conn, Map.new(options))
  def call(conn, %{encryption_password: password, load_app_fn: load_app_fn} = options) when is_binary(password) and is_function(load_app_fn) do
    options = Map.merge(%{hawk: %{}, ticket: %{}}, options)

    conn
    |> Hawk.Request.new()
    |> Hawk.Server.authenticate(load_app_fn, options)
    |> case do
         {:error, {status, msg}} ->
           conn
           |> Conn.resp(status, msg)
           |> Conn.halt()

         {:error, {status, msg, {header, value}}} ->
           conn
           |> Conn.put_resp_header(header, value)
           |> Conn.resp(status, msg)
           |> Conn.halt()

         {:ok, %{credentials: credentials}} ->
           conn
           |> Conn.put_resp_content_type("application/json")
           |> Conn.resp(200, Jason.encode!(Oz.Ticket.issue(credentials, password, options[:ticket])))
    end
  end
end
