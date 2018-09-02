defmodule Oz.Server do
  @moduledoc """
  Documentation for Oz.
  """

  @doc """
  Validate an incoming request

  Options
   * See `Hawk.Server.authenticate/3`
   * `:ticket` any validate option to `Oz.Ticket.parse/2`
  """
  @spec authenticate(Hawk.request(), binary(), keyword() | map()) :: {:ok, %{artifacts: map(), ticket: map()}} | {:error, term()}
  def authenticate(req, password, options \\ %{})
  def authenticate(req, password, options) when is_list(options), do: authenticate(req, password, Map.new(options))
  def authenticate(req, password, options) when is_binary(password) do
    options = Map.merge(%{check_expiration: true, password: password, ticket: %{}}, options)

    req
    |> Hawk.Server.authenticate(Oz.Config, options)
    |> validate_app()
    |> validate_dlg()
  end

  defp validate_app({:error, reason}), do: {:error, reason}
  defp validate_app({:ok, %{credentials: %{app: app}, artifacts: %{app: app}}} = ok), do: ok
  defp validate_app(_ticket), do: {:error, {401, "Mismatching application id", Hawk.Header.error("Mismatching application id")}}

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
end
