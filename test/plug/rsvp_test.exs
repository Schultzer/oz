defmodule PlugOzRSVPTest do
  use ExUnit.Case
  use Plug.Test

  defmodule Config do
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

  defmodule ConfigGrantExpired do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, delegate: true}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "john", exp: Hawk.Now.msec() - :timer.minutes(1)}, ext: %{}}
    end
  end

  defmodule ConfigGrantFail do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, delegate: true}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id), do: nil
  end

  defmodule ConfigGrantAppFail do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, delegate: true}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "network", user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}, ext: %{}}
    end
  end

  defmodule ConfigGrantExpFail do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, delegate: true}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "john"}, ext: %{}}
    end
  end

  defmodule ConfigGrantErrorFail do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, delegate: true}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id) do
      {:error, "boom"}
    end
  end

  defmodule ConfigAppFail do
    use Oz.Config

    def get_credentials("social", _opts) do
      %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, delegate: true}
    end
    def get_credentials("network", _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(_), do: nil

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}, ext: %{}}
    end
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
    apps = %{social: %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256},
             network: %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}}
    %{header: header} = Oz.Client.header("http://example.com/oz/app", :post, apps.social)
    conn = put_req_header(conn(:post, "http://example.com/"), "host", "example.com")
    ticket = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/app", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.App.call(encryption_password: password, config: Config)
             |> Map.get(:resp_body)
             |> decode()

    [conn: conn, apps: apps, encryption_password: password, app_ticket: ticket]
  end

  describe "call/2" do
    test "overrides defaults", %{app_ticket: app_ticket, apps: apps, conn: conn, encryption_password: password} do
      rsvp = Oz.Ticket.rsvp(apps.social, %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: rsvp, ticket: Iron.defaults())
             |> Plug.Conn.send_resp()


      body = conn.resp_body
      assert_received {:plug_conn, :sent}
      assert {200, [{"cache-control", "max-age=0, private, must-revalidate"}, {"content-type", "application/json; charset=utf-8"}], body} == sent_resp(conn)
    end

    test "errors on invalid authentication", %{apps: apps, conn: conn, encryption_password: password} do
      rsvp = Oz.Ticket.rsvp(apps.social, %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}, password, [])
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: rsvp, ticket: Iron.defaults())
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {400, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid header syntax"} == sent_resp(conn)
    end

    test "errors on expired ticket", %{apps: %{social: social}, conn: conn, encryption_password: password} do
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, social)
      application_ticket = conn
                           |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
                           |> put_req_header("authorization", header)
                           |> Plug.Oz.App.call(encryption_password: password, config: Config, ticket: %{Iron.defaults() | ttl: 5})
                           |> Map.get(:resp_body)
                           |> decode()

      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: application_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(social, grant, password)

      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, application_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)

      Process.sleep(10)
      conn = conn
             |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: rsvp, ticket: %{Iron.defaults() | ttl: 5})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Expired ticket\""}], "Expired ticket"} == sent_resp(conn)
    end

    test "errors on missing payload", %{conn: conn, encryption_password: password} do
      conn = conn
             |> Plug.Oz.RSVP.call(encryption_password: password, config: Config)
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {400, [{"cache-control", "max-age=0, private, must-revalidate"}], "Missing required payload"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (request params)", %{app_ticket: app_ticket, apps: apps, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      Oz.Ticket.rsvp(apps.social, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: "")
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {400, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid request payload: rsvp is not allowed to be empty"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (invalid auth)", %{app_ticket: app_ticket, apps: apps, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      Oz.Ticket.rsvp(apps.social, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: "abc")
             |> Plug.Conn.send_resp()


      assert_received {:plug_conn, :sent}
      assert {403, [{"cache-control", "max-age=0, private, must-revalidate"}], "Incorrect number of sealed components"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (user ticket)", %{app_ticket: app_ticket, apps: apps, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: rsvp)
               |> Map.get(:resp_body)
               |> decode()

      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: rsvp)
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"User ticket cannot be used on an application endpoint\""}], "User ticket cannot be used on an application endpoint"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (mismatching apps)", %{app_ticket: app_ticket, apps: apps, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.network, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: rsvp)
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {403, [{"cache-control", "max-age=0, private, must-revalidate"}], "Mismatching ticket and rsvp apps"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (expired rsvp)", %{app_ticket: app_ticket, apps: apps, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, %{ttl: 1})
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)

      Process.sleep(10)
      conn = conn
             |> Plug.Oz.RSVP.call(encryption_password: password, config: Config, rsvp: rsvp)
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {403, [{"cache-control", "max-age=0, private, must-revalidate"}], "Expired rsvp"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (expired grant)", %{app_ticket: app_ticket, apps: apps, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() - :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: ConfigGrantExpired, rsvp: rsvp)
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {403, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (missing grant envelope)", %{app_ticket: app_ticket, apps: apps, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: ConfigGrantFail, rsvp: rsvp, ticket: %{iron: Iron.defaults()})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {403, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (missing grant)", %{app_ticket: app_ticket, apps: apps, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: ConfigGrantFail, rsvp: rsvp, ticket: %{iron: Iron.defaults()})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {403, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (grant app mismatch)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: ConfigGrantAppFail, rsvp: rsvp, ticket: %{iron: Iron.defaults()})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {403, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (grant missing exp)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: ConfigGrantExpFail, rsvp: rsvp, ticket: %{iron: Iron.defaults()})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {403, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (grant error)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: ConfigGrantErrorFail, rsvp: rsvp, ticket: %{iron: Iron.defaults()})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {403, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (app error)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: ConfigAppFail, rsvp: rsvp, ticket: %{iron: Iron.defaults()})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {403, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid application"} == sent_resp(conn)
    end

    test "fails on invalid rsvp (invalid app)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.RSVP.call(encryption_password: password, config: ConfigAppFail, rsvp: rsvp, ticket: %{iron: Iron.defaults()})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {403, [{"cache-control", "max-age=0, private, must-revalidate"}], "Invalid application"} == sent_resp(conn)
    end
  end
end
