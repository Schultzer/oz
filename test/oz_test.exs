defmodule OzTest do
  use ExUnit.Case
  use Plug.Test

  def decode(binary) do
    Jason.decode!(binary, keys: &mixed_keys/1)
  end

  defp mixed_keys(key) do
    try do
      String.to_existing_atom(key)
    rescue
      ArgumentError -> key
    end
  end

  setup do
    Application.put_env(:plug, :validate_header_keys_during_test, true)
    [conn: put_req_header(conn(:post, "http://example.com/"), "host", "example.com"), apps: %{social: %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, delegate: true},
    network: %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}}, password: "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough"]
  end

  describe "Oz" do
    test "runs a full authorization flow", %{conn: conn, apps: apps, password: password} do
      # The app requests an app ticket using Oz.hawk authentication
      options = %{encryption_password: password, load_app_fn: fn (id) -> apps[id] || apps[String.to_existing_atom(id)] end}
      %{header: header} = Oz.Client.header("http://example.com/oz/app", :post, apps.social)
      app_ticket = conn
                   |> Plug.Adapters.Test.Conn.conn(:post, "/oz/app", [])
                   |> put_req_header("authorization", header)
                   |> Plug.Oz.App.call(options)

      refute app_ticket.halted
      # The app refreshes its own ticket
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, decode(app_ticket.resp_body))
      re_app_ticket = conn
                      |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
                      |> put_req_header("authorization", header)
                      |> Plug.Oz.Reissue.call(options)

      refute re_app_ticket.halted
      # The user is redirected to the server, logs in, and grant app access, resulting in an rsvp
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: decode(re_app_ticket.resp_body).app, user: "john", exp: Hawk.Now.msec() + 60000}

      rsvp = Oz.Ticket.rsvp(apps.social, grant, password)

      # After granting app access, the user returns to the app with the rsvp
      options = Map.put(options, :load_grant_fn, fn (_id) -> %{grant: grant, ext: %{public: "everybody knows", private: "the the dice are loaded"}} end)

      # The app exchanges the rsvp for a ticket
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, decode(re_app_ticket.resp_body))
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.Reissue.call(Map.put(options, :rsvp, rsvp))

      refute ticket.halted
      # The app reissues the ticket with delegation to another app
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, decode(ticket.resp_body))
      delegated_ticket = conn
                         |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
                         |> put_req_header("authorization", header)
                         |> Plug.Oz.Reissue.call(Map.put(options, :payload, %{issue_to: apps.network.id, scope: ["a"]}))

      refute delegated_ticket.halted
      # The other app reissues their ticket
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, decode(delegated_ticket.resp_body))
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", []) |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(options)

      refute conn.halted
    end
  end
end
