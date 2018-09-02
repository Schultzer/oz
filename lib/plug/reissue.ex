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
              |> Map.delete(:payload)

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
  defp validate_app({:ok, %{ticket: %{app: app}} = result}, %{config: config} = options) do
    app
    |> config.get_app()
    |> validate_app(result, config, options)
  end

  defp validate_app(app, %{ticket: _ticket}, _config, %{ticket: %{issue_to: issue_to}}) when is_binary(issue_to) and not :erlang.is_map_key(:delegate, app) do
    {:error, {401, "Application has no delegation rights", Hawk.Header.error("Application has no delegation rights")}}
  end
  defp validate_app(%{algorithm: _, id: _, key: _}, %{ticket: %{algorithm: _, id: _, key: _, scope: _, grant: grant} = ticket} = result, config, %{encryption_password: password} = options) do
    grant
    |> config.get_grant()
    |> validate_ticket_grant(ticket, Hawk.Now.msec())
    |> case do
         {:error, reason} ->
          {:error, reason}

         {:ok, %{grant: grant, ext: ext}} ->
           {:ok, %{result | ticket: Oz.Ticket.reissue(ticket, grant, password, Map.merge(options[:ticket], %{ext: ext}))}}
       end
  end
  defp validate_app(%{algorithm: _, id: _, key: _}, %{ticket: %{algorithm: _, id: _, key: _, scope: _} = ticket} = result, _config, %{encryption_password: password} = options) do
    {:ok, %{result | ticket: Oz.Ticket.reissue(ticket, password, options[:ticket])}}
  end
  defp validate_app(_app, _ticket, _config, _options), do: {:error, {401, "Invalid application", Hawk.Header.error("Invalid application")}}

  defp validate_ticket_grant(%{grant: %{app: app, user: user, exp: exp}}, %{app: app, dlg: app, user: user}, now) when exp <= now, do: {:error, {401, "Invalid grant", Hawk.Header.error("Invalid grant")}}
  defp validate_ticket_grant(%{grant: %{app: app, user: user, exp: _exp}, ext: _} = result, %{app: _app, dlg: app, user: user}, _now), do: {:ok, result}
  defp validate_ticket_grant(%{grant: %{app: app, user: user, exp: _exp}, ext: _} = result, %{app: app, user: user}, _now), do: {:ok, result}
  defp validate_ticket_grant(%{grant: %{user: _left}}, %{user: _right}, _now), do: {:error, {401, "Invalid grant", Hawk.Header.error("Invalid grant")}}
  defp validate_ticket_grant(%{grant: %{app: app, exp: _exp}, ext: _} = result, %{app: _app, dlg: app}, _now), do: {:ok, result}
  defp validate_ticket_grant(%{grant: %{app: app, exp: _exp}, ext: _} = result, %{app: app}, _now), do: {:ok, result}
  defp validate_ticket_grant(_grant, _ticket, _now), do: {:error, {401, "Invalid grant", Hawk.Header.error("Invalid grant")}}
end
