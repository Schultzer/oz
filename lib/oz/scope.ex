defmodule Oz.Scope do
  @moduledoc """
  Documentation for Oz.
  """

  @doc false
  @spec valid?(list(), list()) :: true | {:error, binary()}
  def valid?(scope, acc \\ [])
  def valid?([], _acc),                                    do: true
  def valid?(scope, _acc) when not is_list(scope),         do: {:error, {500, "scope not instance of Array"}}
  def valid?([s | _scope], _acc) when not is_binary(s),    do: {:error, {400, "scope item is not a string"}}
  def valid?([s | _scope], _acc) when s == nil or s == "", do: {:error, {400, "scope includes null or empty string value"}}
  def valid?([s | scope], acc) do
    case s in acc do
      true  -> {:error, {400, "scope includes duplicated item"}}

      false -> valid?(scope, [s | acc])
    end
  end
  def valid?([], []), do: {:error, "null scope"}

  @spec validate(list(), list()) :: [binary()] | {:error, binary()}
  def validate(scope, acc \\ [])
  def validate([], scope),           do: scope
  def validate(["" | _scope], _acc), do: {:error, "Empty string value"}
  def validate([s | scope], acc) when is_binary(s) do
    case s in acc do
      true  -> {:error, {400, "Scope includes duplicated item"}}

      false -> validate(scope, [s | acc])
    end
  end

  @spec is_subset([binary()], [binary()]) :: [binary()] | {:error, binary()}
  def is_subset(_left, []),                                     do: {:error, {500, "grant scope is not a subset of the application scope"}}
  def is_subset(left, right) when length(left) > length(right), do: {:error, {500, "grant scope is not a subset of the application scope"}}
  def is_subset(left, right) when is_list(left) and is_list(right) do
    common = for r <- right, r in left, do: r
    case length(common) === length(left) do
      false -> {:error, {500, "grant scope is not a subset of the application scope"}}

      true  -> left
    end
  end

  def is_subset?(scope, _) when not is_list(scope),              do: false
  def is_subset?([], _),                                         do: false
  def is_subset?(left, right) when length(left) < length(right), do: false
  def is_subset?(left, right) do
    common = for l <- left, l in right, do: l
    length(common) === length(right)
  end

  def is_equal?(scope, scope),  do: true
  def is_equal?(_left, _right), do: false


  @spec get(map(), map()) :: list() | {:error, binary()}
  def get(left, right \\ %{})
  def get(%{scope: scope}, %{scope: scope}), do: validate(scope)
  def get(%{scope: grant}, %{scope: app}),   do: grant |> validate() |> is_subset(app)
  def get(%{scope: scope}, _),               do: validate(scope)
  def get(_, %{scope: scope}),               do: validate(scope)
  def get(_grant, _app),                     do: []
end
