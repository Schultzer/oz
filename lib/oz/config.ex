defmodule Oz.Config do
  @moduledoc """
  The Oz.Config implements two callbacks.

  ## Examples

  ### `get_app/1`

  ### `get_grant/1`
  """
  @callback get_app(binary()) :: Oz.app() | nil
  @callback get_grant(binary()) :: %{grant: Oz.grant(), ext: map()} | nil

  @doc false
  defmacro __using__(_) do
    quote do
      use Hawk.Config
      @behaviour unquote(__MODULE__)

      defoverridable unquote(__MODULE__)
    end
  end

  use Hawk.Config

  def get_credentials(id, %{password: password, ticket: ticket} = options) do
    id
    |> Oz.Ticket.parse(password, ticket)
    |> check_expiration(options)
  end
  def get_credentials(_id, _options), do: {:error, {500, "Missing options"}}

  defp check_expiration(%{exp: exp} = ticket, %{check_expiration: true}) do
    case exp <= Hawk.Now.msec() do
      true  -> {:error, {401, "Expired ticket", Hawk.Header.error("Expired ticket")}}

      false -> ticket
    end
  end
  defp check_expiration(ticket, _options), do: ticket
end

