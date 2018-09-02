defmodule Oz do
  @moduledoc """
  Documentation for Oz.
  """

  @typedoc """
  Application is a map with following keys.
    * `:id` the application identifier.
    * `:scope` a list with the default application scope.
    * `:delegate` if true, the application is allowed to delegate a ticket to another application. Defaults to false.
    * `:key` the shared secret used to authenticate.
    * `:algorithm` the HMAC algorithm used to authenticate.
  """
  @type app :: %{id: binary(), scope: [binary()],  delegate: boolean(), key: binary(), algorithm: atom()}

  @typedoc """
  User grant is a map with following keys.
    * `:id` the grant identifier.
    * `:app` the application identifier.
    * `:user` the user identifier.
    * `:exp` grant expiration time in milliseconds since 1/1/1970.
    * `:scope` a list with the scope granted by the user to the application.
  """
  @type grant :: %{id: binary(), app: binary(), user: binary(), exp: integer(), scope: [binary()]}

  @typedoc """
  Ticket and its public properties.
    * `:id` the ticket identifier used for making authenticated Hawk requests.
    * `:key` a shared secret used to authenticate.
    * `:algorithm` the HMAC algorithm used to authenticate.
    * `:exp` ticket expiration time in milliseconds since 1/1/1970.
    * `:app` the application id the ticket was issued to.
    * `:user` the user id if the ticket represents access to user resources. If no user id is included, the ticket allows the application access to the application own resources only.
    * `:scope` the ticket scope. Defaults to [] if no scope is specified.
    * `:grant` if user is set, includes the grant identifier referencing the authorization granted by the user to the application. Can be a unique identifier or string encoding the grant information as long as the server is able to parse the information later.
    * `:delegate` if false, the ticket cannot be delegated regardless of the application permissions. Defaults to true which means use the application permissions to delegate.
    * `:dlg` if the ticket is the result of access delegation, the application id of the delegating application.
    * `:ext` custom server public data attached to the ticket.
  """
  @type ticket :: %{id: binary(), key: binary(), algorithm: atom(), exp: integer(), app: binary(), user: binary(), scope: [binary()], grant: binary(), delegate: boolean(), dlg: binary(), ext: map()}
end
