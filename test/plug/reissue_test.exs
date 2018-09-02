defmodule PlugOzReissueTest do
  use ExUnit.Case
  use Plug.Test

  defmodule Config do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}, ext: %{}}
    end
  end

  defmodule ConfigDlgFail do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(_id), do: get_credentials("social", %{})

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}, ext: %{}}
    end
  end



  defmodule ConfigApplication do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, delegate: true}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}, ext: %{}}
    end
  end

  defmodule ConfigApplicationGrantAppFail do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, delegate: true}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "xyz", user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}, ext: %{}}
    end
  end


  defmodule ConfigAppFail do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(_id), do: nil

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}, ext: %{}}
    end
  end

  defmodule ConfigGrantFail do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}}
    end
  end

  defmodule ConfigGrantUserFail do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "steve", exp: Hawk.Now.msec() + :timer.minutes(1)}, ext: %{}}
    end
  end

  defmodule ConfigGrantExpFail do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "steve"}, ext: %{}}
    end
  end

  defmodule ConfigGrantAppFail do
    use Oz.Config

    def get_app(_), do: %{}

    def get_grant(_), do: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "xyz", user: "john"}
    def get_credentials(_id, _opts), do: nil
  end

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
    password = "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough"
    # %{header: header} = Oz.Client.header("http://example.com/oz/app", :post, apps.social)
    # conn = put_req_header(conn(:post, "http://example.com/"), "host", "example.com")
    # ticket = conn
    #          |> Plug.Adapters.Test.Conn.conn(:post, "/oz/app", [])
    #          |> put_req_header("authorization", header)
    #          |> Plug.Oz.App.call(encryption_password: password, config: Config)
    #          |> Map.get(:resp_body)
    #          |> decode()
    [
      app_ticket: Oz.Ticket.issue(Config.get_app("social"), password, %{}),
      encryption_password: password,
      conn: put_req_header(conn(:post, "http://example.com/"), "host", "example.com")
    ]
  end

  describe "call/2" do
    test "allows null payload", %{app_ticket: app_ticket, conn: conn, encryption_password: password} do
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(encryption_password: password, config: Config)
             |> Plug.Conn.resp(200, "REISSUED")
             |> Plug.Conn.send_resp()

      refute conn.halted
      assert_received {:plug_conn, :sent}
      assert {200, [{"cache-control", "max-age=0, private, must-revalidate"}, {"content-type", "application/json; charset=utf-8"}], "REISSUED"} == sent_resp(conn)
    end

    test "overrides defaults", %{app_ticket: app_ticket, conn: conn, encryption_password: password} do
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(encryption_password: password, config: Config, ticket: %{ttl: :timer.minutes(10), iron: Iron.defaults()}, hawk: %{})
             |> Plug.Conn.resp(200, "REISSUED")
             |> Plug.Conn.send_resp()

      refute conn.halted
      assert_received {:plug_conn, :sent}
      assert {200, [{"cache-control", "max-age=0, private, must-revalidate"}, {"content-type", "application/json; charset=utf-8"}], "REISSUED"} == sent_resp(conn)
    end

    test "reissues expired ticket", %{conn: conn, encryption_password: password} do
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, Config.get_app("social"))
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.App.call(encryption_password: password, config: Config, ticket: %{ttl: 5})
               |> Map.get(:resp_body)
               |> decode()

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)

      Process.sleep(10)
      conn = conn
             |> Plug.Oz.Reissue.call(encryption_password: password, config: Config, ticket: %{ttl: 5})
             |> Plug.Conn.resp(200, "REISSUED")
             |> Plug.Conn.send_resp()

      refute conn.halted
      assert_received {:plug_conn, :sent}
      assert {200, [{"cache-control", "max-age=0, private, must-revalidate"}, {"content-type", "application/json; charset=utf-8"}], "REISSUED"} == sent_resp(conn)
    end

    test "fails on app load error", %{app_ticket: app_ticket, conn: conn, encryption_password: password} do
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(encryption_password: password, config: ConfigAppFail)
             |> Plug.Conn.send_resp()

      assert conn.halted
      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid application\""}], "Invalid application"} == sent_resp(conn)
    end

    test "fails on missing app delegation rights", %{app_ticket: app_ticket, conn: conn, encryption_password: password} do
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(encryption_password: password, config: ConfigDlgFail, payload: %{issue_to: "network"})
             |> Plug.Conn.send_resp()

      assert conn.halted
      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Application has no delegation rights\""}], "Application has no delegation rights"} == sent_resp(conn)
    end

    # test "fails on invalid reissue (request params)", %{app_ticket: app_ticket, conn: conn, encryption_password: password} do
    #   options = %{encryption_password: password, load_app_fn: fn id -> apps[String.to_atom(id)] end, payload: %{issue_to: nil}}
    #   %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
    #   conn = conn
    #          |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
    #          |> put_req_header("authorization", header)

    #   assert Plug.Oz.reissue(conn, options) == {:error, "Invalid request payload: issueTo must be a string"}
    # end

    test "fails on invalid reissue (fails auth)", %{app_ticket: app_ticket, conn: conn} do
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(encryption_password: "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough_x", config: Config)
             |> Plug.Conn.send_resp()

      assert conn.halted
      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Bad hmac value\""}], "Bad hmac value"} == sent_resp(conn)
    end

    test "fails on invalid reissue (invalid app)", %{app_ticket: app_ticket, conn: conn, encryption_password: password} do
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(encryption_password: password, config: ConfigAppFail)
             |> Plug.Conn.send_resp()

      assert conn.halted
      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid application\""}], "Invalid application"} == sent_resp(conn)
    end

    test "fails on invalid reissue (missing grant)", %{app_ticket: app_ticket, conn: conn, encryption_password: password} do
      rsvp = Oz.Ticket.rsvp(Config.get_app("social"), Config.get_grant("").grant, password, encryption_password: password, config: Config)
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: rsvp)
               |> Map.get(:resp_body)
               |> decode()

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(encryption_password: password, config: ConfigGrantFail)
             |> Plug.Conn.send_resp()

      assert conn.halted
      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid grant\""}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid reissue (grant error)", %{app_ticket: app_ticket, conn: conn, encryption_password: password} do
      rsvp = Oz.Ticket.rsvp(Config.get_app("social"), Config.get_grant("").grant, password, encryption_password: password, config: Config)
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: rsvp)
               |> Map.get(:resp_body)
               |> decode()

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(encryption_password: password, config: ConfigGrantFail)
             |> Plug.Conn.send_resp()

      assert conn.halted
      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid grant\""}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid reissue (grant user mismatch)", %{app_ticket: app_ticket, conn: conn, encryption_password: password} do
      rsvp = Oz.Ticket.rsvp(Config.get_app("social"), Config.get_grant("").grant, password, encryption_password: password, config: Config)

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: rsvp)
               |> Map.get(:resp_body)
               |> decode()

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(encryption_password: password, config: ConfigGrantUserFail)
             |> Plug.Conn.send_resp()

      assert conn.halted
      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid grant\""}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid reissue (grant missing exp)", %{app_ticket: app_ticket, conn: conn, encryption_password: password} do
      rsvp = Oz.Ticket.rsvp(Config.get_app("social"), Config.get_grant("").grant, password, encryption_password: password, config: Config)
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: rsvp)
               |> Map.get(:resp_body)
               |> decode()

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(encryption_password: password, config: ConfigGrantExpFail)
             |> Plug.Conn.send_resp()

      assert conn.halted
      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid grant\""}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid reissue (grant app does not match app or dlg)", %{conn: conn, encryption_password: password} do
      %{header: header} = Oz.Client.header("http://example.com/oz/app", :post, ConfigApplication.get_app("social"))

      # The app requests an app ticket using Oz.hawk authentication
      applications_ticket = conn
                            |> Plug.Adapters.Test.Conn.conn(:post, "/oz/app", [])
                            |> put_req_header("authorization", header)
                            |> Plug.Oz.App.call(encryption_password: password, config: ConfigApplication)
                            |> Map.get(:resp_body)
                            |> decode()

      # The user is redirected to the server, logs in, and grant app access, resulting in an rsvp
      rsvp = Oz.Ticket.rsvp(ConfigApplication.get_app("social"), Config.get_grant("").grant, password, [])

      # After granting app access, the user returns to the app with the rsvp
      # The app exchanges the rsvp for a ticket
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, applications_ticket)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.RSVP.call(encryption_password: password, config: ConfigApplication, rsvp: rsvp)
               |> Map.get(:resp_body)
               |> decode()

      # The app reissues the ticket with delegation to another app
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      delegated_ticket = conn
                         |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
                         |> put_req_header("authorization", header)
                         |> Plug.Oz.Reissue.call(encryption_password: password, config: ConfigApplication, payload: %{issue_to: "network"})
                         |> Map.get(:resp_body)
                         |> decode()

      # The other app reissues their ticket
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, delegated_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(encryption_password: password, config: ConfigApplicationGrantAppFail)
             |> Plug.Conn.send_resp()

      assert conn.halted
      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid grant\""}], "Invalid grant"} == sent_resp(conn)
    end
  end
end
