defmodule Plug.Oz.RSVP do
  @moduledoc false

  @behaviour Plug

  alias Plug.Conn

  def init(opts) do
    Map.new(opts)
  end

  def call(conn, options) when is_list(options), do: call(conn, Map.new(options))
  def call(conn, %{rsvp: <<>>}) do
    conn
    |> Conn.resp(400, "Invalid request payload: rsvp is not allowed to be empty")
    |> Conn.halt()
  end
  def call(conn, %{encryption_password: password, rsvp: rsvp} = options) when is_binary(password) and is_binary(rsvp) do
    options = Map.merge(%{ticket: %{}}, options)

    conn
    |> Hawk.Request.new()
    |> Oz.Server.authenticate(password, options)
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

         {:ok, %{ticket: %{user: _}}}          ->
          {header, value} = Hawk.Header.error("User ticket cannot be used on an application endpoint")
          conn
          |> Conn.put_resp_header(header, value)
          |> Conn.resp(401, "User ticket cannot be used on an application endpoint")
          |> Conn.halt()

         {:ok, %{ticket: %{app: _} = ticket}}  ->
           rsvp
           |> Oz.Ticket.parse(password, options[:ticket] || %{})
           |> validate(ticket, Hawk.Now.msec(), options)
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

                 {:ok, ticket} ->
                   conn
                   |> Conn.put_resp_content_type("application/json")
                   |> Conn.resp(200, Jason.encode!(ticket))
              end
      end
  end
  def call(conn, _options) do
    conn
    |> Conn.resp(400, "Missing required payload")
    |> Conn.halt()
  end

  @spec validate(map() | {:error, term()}, map(), integer(), map()) ::  {:ok, map()} | {:error, term()}
  defp validate({:error, {_status, "Incorrect number of sealed components"}}, _ticket, _now, _options), do: {:error, {403, "Incorrect number of sealed components"}}
  defp validate({:error, reason}, _ticket, _now, _options),                                             do: {:error, reason}
  defp validate(%{exp: exp, app: app}, %{app: app}, now, _options) when exp <= now,                     do: {:error, {403, "Expired rsvp"}}
  defp validate(%{grant: grant, app: app}, %{app: app}, now, %{encryption_password: password, ticket: ticket, config: config}) do
    case config.get_grant(grant) do
      %{grant: %{exp: exp}} when exp <= now              -> {:error, {403, "Invalid grant"}}

      %{grant: %{app: grant_app}} when grant_app !== app -> {:error, {403, "Invalid grant"}}

      %{grant: %{app: app, exp: _} = grant, ext: ext}                     ->
        case config.get_app(app) do
          %{id: _} = app -> {:ok, Oz.Ticket.issue(app, grant, password, Map.merge(ticket, %{ext: ext}))}

          _              -> {:error, {403, "Invalid application"}}
        end


       _                                       -> {:error, {403, "Invalid grant"}}
    end
  end
  defp validate(_rsvp, _ticket, _now, _options), do: {:error, {403, "Mismatching ticket and rsvp apps"}}
end
