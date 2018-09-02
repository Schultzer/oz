defmodule Oz.Scope do
  @moduledoc false

  @doc false
  @spec validate(list(), list()) :: [binary()] | {:error, binary()}
  def validate(scope, acc \\ [])
  def validate([], scope), do: scope
  def validate([s | scope], acc) when is_binary(s) and byte_size(s) > 0 do
    case s in acc do
      true  -> {:error, {400, "Scope includes duplicated item"}}

      false -> validate(scope, [s | acc])
    end
  end
  def validate([s | _scope], _acc), do: {:error, {400, "Scope includes #{inspect s}"}}

  @doc false
  @spec is_subset({:error, term} | [binary()], [binary()]) :: [binary()] | {:error, binary()}
  def is_subset({:error, reason}, _), do: {:error, reason}
  def is_subset(_left, []), do: {:error, {500, "Grant scope is not a subset of the application scope"}}
  def is_subset(left, right) when is_list(left) and is_list(right) do
    case left -- right do
      []  -> left

      _   -> {:error, {500, "Grant scope is not a subset of the application scope"}}
    end
  end

  @doc false
  @spec get(map(), map()) :: list() | {:error, binary()}
  def get(left, right \\ %{})
  def get(%{scope: scope}, %{scope: scope}), do: validate(scope)
  def get(%{scope: grant}, %{scope: app}),   do: grant |> validate() |> is_subset(app)
  def get(%{scope: scope}, _),               do: validate(scope)
  def get(_, %{scope: scope}),               do: validate(scope)
  def get(_grant, _app),                     do: []
end
