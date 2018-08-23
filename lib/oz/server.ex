defmodule Oz.Server do
  @moduledoc """
  Documentation for Oz.
  """

  @doc """
  Validate an incoming request

  Options
   * `:ticket`
   * `:hawk`
  """
  @spec authenticate(Hawk.request(), binary(), keyword() | map()) :: {:ok, %{artifacts: map(), ticket: map()}} | {:error, term()}
  def authenticate(req, password, options \\ %{})
  def authenticate(req, password, options) when is_list(options), do: authenticate(req, password, Map.new(options))
  # def authenticate(_req, password, _options) when not is_binary(password), do: {:error, "invalid encryption password"}
  def authenticate(req, password, options) when is_binary(password) do
    options = Map.merge(%{check_expiration: true, ticket: %{}, hawk: %{}}, options)
    credentials_fn = fn id -> id |> Oz.Ticket.parse(password, options[:ticket]) |> check_expiration(options) end

    req
    |> Hawk.Server.authenticate(credentials_fn, options[:hawk])
    |> validate_app()
    |> validate_dlg()
  end

  defp validate_app({:error, reason}), do: {:error, reason}
  defp validate_app({:ok, %{credentials: %{app: left}, artifacts: %{app: right}}}) when left !== right, do: {:error, {401, "Mismatching application id", Hawk.Header.error("Mismatching application id")}}
  defp validate_app(ticket), do: ticket

  defp validate_dlg({:error, reason}), do: {:error, reason}
  defp validate_dlg({:ok, %{credentials: %{dlg: dlg} = ticket, artifacts: %{dlg: dlg} = artifacts}}), do: {:ok, %{ticket: ticket, artifacts: artifacts}}
  defp validate_dlg({:ok, %{credentials: %{dlg: _left}, artifacts: %{dlg: _right}}}), do: {:error, {401, "Mismatching delegated application id", Hawk.Header.error("Mismatching delegated application id")}}
  defp validate_dlg({:ok, %{credentials: credentials, artifacts: artifacts}}) do
    cond do
      Map.has_key?(credentials, :dlg) and not Map.has_key?(artifacts, :dlg) -> {:error, {401, "Mismatching delegated application id", Hawk.Header.error("Mismatching delegated application id")}}

      not Map.has_key?(credentials, :dlg) and Map.has_key?(artifacts, :dlg) -> {:error, {401, "Mismatching delegated application id", Hawk.Header.error("Mismatching delegated application id")}}

      true                                                                  -> {:ok, %{ticket: credentials, artifacts: artifacts}}
    end
  end

  defp check_expiration(%{exp: exp} = ticket, %{check_expiration: true}) do
    case exp <= Hawk.Now.msec() do
      true  -> {:error, {401, "Expired ticket", Hawk.Header.error("Expired ticket")}}

      false -> ticket
    end
  end
  defp check_expiration(ticket, _check_expiration), do: ticket
end
