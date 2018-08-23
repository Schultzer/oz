defmodule Oz.Ticket do
  @moduledoc """
  Documentation for Oz.
  """

  @typedoc """
  `:exp`       Time in msec
  `:app`       App id ticket is issued to
  `:scope`     Ticket scope
  `:grant`     Grant id
  `:user`      User id
  `:dlg`       App id of the delegating party
  `:key`       Ticket secret key (Hawk)
  `:algorithm` Ticket hmac algorithm (Hawk)
  `:id`        Ticket key id (Hawk)
  `:ext`       Application data `:public` `:private`
  """
  @type t :: %{exp: pos_integer(), app: binary(), scope: [binary(), ...], grant: binary(), user: binary(), dlg: boolean(), key: binary(), algorithm: atom(), id: binary(), ext: map()}

  @typedoc """
  `:id`   Application id
  `scope` Application scope
  """
  @type app :: %{id: binary(), scope: [binary(), ...]}

  @typedoc """
  `:id`   Persistent identifier used to issue additional tickets or revoke access
  `:user` User id
  `:exp`  Grant expiration
  `scope` Grant scope
  """
  @type grant :: %{id: binary(), user: binary, exp: pos_integer(), scope: [binary(), ...]}

  @defaults %{ticket_ttl: :timer.hours(1), rsvp_ttl: :timer.minutes(1), key_bytes: 32, hmac_algorithm: :sha256}

  @doc """
  Ticket defualts.

  ## Examples

      iex> Oz.Ticket.defaults()
      %{ticket_ttl: 3600000, rsvp_ttl: 60000, key_bytes: 32, hmac_algorithm: :sha256}
  """
  @spec defaults() :: %{ticket_ttl: 3600000, rsvp_ttl: 60000, key_bytes: 32, hmac_algorithm: :sha256}
  def defaults, do: @defaults


  @doc """
  Issues a new ticket for an map cointaing `:app` `Oz.Ticket.app()` or `:app` and `:grant` `Oz.Ticket.grant()`

  Options
    * `:ttl` time to live defualts to `:timer.hours(1)`
    * `:delegate` Ticket-specific delegation permission (default to true)
    * `:ext` Server-specific extension data
      * `:public` Included in the plain ticket
      * `:private` Included in the encoded ticket
    * `:iron` Override Iron defaults
    * `:key_bytes` Hawk key length defaults to `32`
    * `:hmac_algorithm` Hawk algorithm defaults to `:sha256`

  ## Examples
      iex> app = %{id: "123", scope: ['a", "b"]}
      iex> options = %{ttl: :timer.minutes(1), delegate: false, ext: %{public: %{tos: '0.0.1'}, private: %{x: 1}}, key_bytes: 32, hmac_algorithm: :sha256}
      iex> Oz.Ticket.issue(app, passwornd options)
      %{ticket_ttl: 3600000, rsvp_ttl: 60000, key_bytes: 32, hmac_algorithm: :sha256}
  """
  @spec issue(map(), binary(), keyword() | map()) :: map() | {:error, binary()}
  def issue(app, password, options) when is_list(options), do: issue(app, password, Map.new(options))
  def issue(%{id: _} = app, password, options) when is_binary(password) do
    app
    |> Oz.Scope.get()
    |> __issue__(app, password, options)
  end

  @doc """
  Issues a new ticket for an map cointaing `:app` `Oz.Ticket.app()` or `:app` and `:grant` `Oz.Ticket.grant()`

  Options
    * `:ttl` time to live defualts to `:timer.hours(1)`
    * `:delegate` Ticket-specific delegation permission (default to true)
    * `:ext` Server-specific extension data
      * `:public` Included in the plain ticket
      * `:private` Included in the encoded ticket
    * `:iron` Override Iron defaults
    * `:key_bytes` Hawk key length defaults to `32`
    * `:hmac_algorithm` Hawk algorithm defaults to `:sha256`

  ## Examples
      iex> app = %{id: "123", scope: ['a", "b"]}
      iex> options = %{ttl: :timer.minutes(1), delegate: false, ext: %{public: %{tos: '0.0.1'}, private: %{x: 1}}, key_bytes: 32, hmac_algorithm: :sha256}
      iex> Oz.Ticket.issue(app, passwornd options)
      %{ticket_ttl: 3600000, rsvp_ttl: 60000, key_bytes: 32, hmac_algorithm: :sha256}
  """
  @spec issue(map(), map(), binary(), keyword() | map()) :: map() | {:error, binary()}
  def issue(app, grant, password, options) when is_list(options), do: issue(app, grant, password, Map.new(options))
  def issue(%{id: _} = app, %{id: _, user: _, exp: _} = grant, password, options) when is_binary(password) do
    grant
    |> Oz.Scope.get(app)
    |> __issue__(app, grant, password, options)
  end

  defp __issue__({:error, reason}, _app, _password, _options), do: {:error, reason}
  defp __issue__(scope, %{id: app}, password, options) do
    exp = Hawk.Now.msec() + (options[:ttl] || :timer.hours(1))
    generate(%{app: app, exp: exp, delegate: Map.get(options, :delegate, true), scope: scope}, password, options)
  end

  defp __issue__({:error, reason}, _app, _grant, _password, _options), do: {:error, reason}
  defp __issue__(scope, %{id: app}, %{id: grant, user: user, exp: exp}, password, options) do
    exp = Hawk.Now.msec() + (options[:ttl] || :timer.hours(1)) |> Kernel.min(exp)
    generate(%{app: app, exp: exp, delegate: Map.get(options, :delegate, true), grant: grant, user: user, scope: scope}, password, options)
  end

  @doc """
  Reissue a `Oz.Ticket.t()`

  Options
    * `:ttl` time to live defualts to `:timer.hours(1)`
    * `:delegate` Ticket-specific delegation permission (default to true)
    * `:ext` Server-specific extension data
      * `:public` Included in the plain ticket
      * `:private` Included in the encoded ticket
    * `:iron` Override Iron defaults
    * `:key_bytes` Hawk key length defaults to `32`
    * `:hmac_algorithm` Hawk algorithm defaults to `:sha256`

  ## Examples

      iex> grant = %{id: "d832d9283hd9823dh", user: "456", exp: 1352535473414, scope: ["b"]}
      iex> options = %{ttl: :timer.minutes(1), delegate: false, ext: %{public: %{tos: '0.0.1'}, private: %{x: 1}}, key_bytes: 32, hmac_algorithm: :sha256}
      iex> Oz.Ticket.reissue(ticket, grant, options)
      %{ticket_ttl: 3600000, rsvp_ttl: 60000, key_bytes: 32, hmac_algorithm: :sha256}
  """
  @spec reissue(map(), binary(), keyword() | map()) :: map() | {:error, binary()}
  def reissue(parent_ticket, password, options) when is_list(options),           do: reissue(parent_ticket, password, Map.new(options))
  def reissue(_parent_ticket, password, _options) when not is_binary(password),  do: {:error, {500, "Invalid encryption password"}}
  def reissue(%{delegate: false}, _password, %{delegate: _}),                    do: {:error, {403, "Cannot override ticket delegate restriction"}}
  def reissue(%{delegate: false}, _password, %{issue_to: _}),                    do: {:error, {403, "Ticket does not allow delegation"}}
  def reissue(%{dlg: _}, _password, %{issue_to: _}),                             do: {:error, {400, "Cannot re-delegate"}}
  def reissue(parent_ticket, password, options) when is_binary(password) do
    options
    |> Oz.Scope.get(parent_ticket)
    |> __reissue__(parent_ticket, password, options)
  end

  @spec reissue(map(), map(), binary(), keyword() | map()) :: map() | {:error, binary()}
  def reissue(parent_ticket, grant, password, options) when is_list(options),            do: reissue(parent_ticket, grant, password, Map.new(options))
  def reissue(_parent_ticket, _grant, password, _options) when not is_binary(password),  do: {:error, {500, "Invalid encryption password"}}
  def reissue(%{delegate: false}, _grant, _password, %{delegate: _}),                    do: {:error, {403, "Cannot override ticket delegate restriction"}}
  def reissue(%{delegate: false}, _grant, _password, %{issue_to: _}),                    do: {:error, {403, "Ticket does not allow delegation"}}
  def reissue(%{dlg: _}, _grant, _password, %{issue_to: _}),                             do: {:error, {400, "Cannot re-delegate"}}
  def reissue(%{grant: grant}, %{id: id}, _password, _options) when grant !== id,        do: {:error, {500, "Parent ticket grant does not match options.grant"}}
  def reissue(parent_ticket, grant, password, options) when is_binary(password) do
    options
    |> Oz.Scope.get(parent_ticket)
    |> __reissue__(parent_ticket, grant, password, options)
  end

  defp __reissue__({:error, _reason}, _parent_ticket, _password, %{scope: _scope}), do: {:error, {403, "New scope is not a subset of the parent ticket scope"}}
  defp __reissue__({:error, reason}, _parent_ticket, _password, _options), do: {:error, reason}
  defp __reissue__(scope, parent_ticket, password, options) do
    options = parent_ticket |> Map.take([:ext]) |> Map.merge(options)

    %{scope: scope}
    |> put_exp(parent_ticket, options)
    |> put_dlg(parent_ticket, options)
    |> put_app(parent_ticket, options)
    |> put_delegate(parent_ticket, options)
    |> generate(password, options)
  end

  defp __reissue__({:error, _reason}, _parent_ticket, _grant, _password, %{scope: _scope}), do: {:error, {403, "New scope is not a subset of the parent ticket scope"}}
  defp __reissue__({:error, reason}, _parent_ticket, _grant, _password, _options), do: {:error, reason}
  defp __reissue__(scope, parent_ticket, %{id: id, user: user}, password, options) do
    options = parent_ticket |> Map.take([:ext]) |> Map.merge(options)

    %{scope: scope, grant: id, user: user}
    |> put_exp(parent_ticket, options)
    |> put_dlg(parent_ticket, options)
    |> put_app(parent_ticket, options)
    |> put_delegate(parent_ticket, options)
    |> generate(password, options)
  end

  def put_exp(reissue, %{grant: %{exp: exp}}, options) do
    Map.put(reissue, :exp, options |> get_exp() |> Kernel.min(exp))
  end
  def put_exp(reissue, _parent_ticket, options) do
    Map.put(reissue, :exp, get_exp(options))
  end

  def put_dlg(reissue, %{app: app}, %{issue_to: _}) do
    Map.put(reissue, :dlg, app)
  end
  def put_dlg(reissue, %{dlg: dlg}, _options) do
    Map.put(reissue, :dlg, dlg)
  end
  def put_dlg(reissue, _parent_ticket, _options) do
    reissue
  end

  def put_app(reissue, _parent_ticket, %{issue_to: app}) do
    Map.put(reissue, :app, app)
  end
  def put_app(reissue, %{app: app}, _options) do
    Map.put(reissue, :app, app)
  end

  def put_delegate(reissue, _parent_ticket, %{delegate: false}) do
    Map.put(reissue, :delegate, false)
  end
  def put_delegate(reissue, %{delegate: false}, _options) do
    Map.put(reissue, :delegate, false)
  end
  def put_delegate(reissue, _parent_ticket, _options) do
    Map.put(reissue, :delegate, true)
  end

  def get_exp(%{ttl: ttl}), do: Hawk.Now.msec() + ttl
  def get_exp(_),           do: Hawk.Now.msec() + :timer.hours(1)


  @doc """
  The requesting application

  Options
    * `:ttl` Rsvp TTL defaults to `:timer.minutes(1)`
    * `:iron` Override Iron defaults

  ## Examples

      iex> Oz.Ticket.rsvp(app, grant, "password", options)
  """
  @spec rsvp(map(), map(), binary(), keyword()) :: map() | {:error, binary()}
  def rsvp(app, grant, password, options \\ [])
  # def rsvp(%{}, _grant, _password, _options), do: {:error, "invalid application object"}
  # def rsvp(_app, %{}, _password, _options), do: {:error, "invalid grant object"}
  # def rsvp(_app, _grant, password, _options) when not is_binary(password), do: {:error, "invalid encryption password"}
  def rsvp(%{id: app}, %{id: grant}, password, options) when is_binary(password) do
    exp     = Hawk.Now.msec() + Access.get(options, :ttl, :timer.minutes(1))
    options = Access.get(options, :iron, Iron.defaults())
    Iron.seal(%{app: app, exp: exp, grant: grant}, password, options)
  end

  @doc """
  Generate a `Oz.Ticket.t()` takes a map with `:exp`, `:app`, `:scope`, `:grant`, `:user` and `:dlg`
  and returns a generated `Oz.Ticket.t()`

  Options
    * `:hmac_algorithm` Hawk algorithm defualts to `:sha256`
    * `:key_bytes` Hawk key length defualts to `32`
    * `:iron` Override Iron defaults

  ## Examples

      iex> Oz.Ticket.generate(%{exp: :timer.hours(1), app: "123", scope ["a", "b"], grant: "d832d9283hd9823dh", user: "234", dlg: true}, "password")
      %{}
  """
  @spec generate(map(), binary(), map()) :: map()
  def generate(ticket, password, options \\ %{})
  def generate(ticket, password, options) when is_list(options), do: generate(ticket, password, Map.new(options), 0)
  def generate(ticket, password, options) when is_map(options),  do: generate(ticket, password, options, 0)

  defp generate(ticket, password, options, 0 = pos) do
    random = Kryptiles.random_string(options[:key_bytes] || 32)
    ticket
    |> Map.merge(%{algorithm: options[:hmac_algorithm] || :sha256, key: random})
    |> generate(password, options, pos + 1)
  end
  defp generate(ticket, password, %{ext: ext} = options, 1 = pos) do
    ticket
    |> Map.merge(%{ext: ext})
    |> generate(password, options, pos + 1)
  end
  defp generate(ticket, password, options, 2 = pos) do
    ticket
    |> Map.merge(%{id: Iron.seal(ticket, password, options[:iron] || Iron.defaults)})
    |> generate(password, options, pos + 1)
  end
  defp generate(ticket, _password, %{ext: %{public: public}}, 3), do: %{ticket | ext: public}
  defp generate(ticket, _password, _options, 3),                  do: Map.delete(ticket, :ext)
  defp generate(ticket, password, options, pos),                  do: generate(ticket, password, options, pos + 1)


  @doc """
  Parse ticket id

  Options
    * `:iron` Override Iron defaults

  ## Examples

      iex> Oz.Ticket.parse("", "password")
      %{}
  """
  @spec parse(binary(), binary(), keyword()) :: map() | {:error, term()}
  def parse(id, password, options \\ [])
  # def parse(_id, password, _options) when not is_binary(password), do: Hawk.InternalServerError.error("invalid encryption password")
  def parse(id, password, options) when is_binary(password) do
    id
    |> Iron.unseal(password, options[:iron] || Iron.defaults())
    |> case do
         m when is_map(m)                  -> Map.put(m, :id, id)

         {:error, {500, "Bad hmac value" = msg}} -> {:error, {401, msg, Hawk.Header.error(msg)}}

         err                               ->  err
       end
  end
end
