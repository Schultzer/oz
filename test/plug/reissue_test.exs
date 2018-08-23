defmodule PlugOzReissueTest do
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

    password = "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough"
    apps = %{social: %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256},
             network: %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}}
    %{header: header} = Oz.Client.header("http://example.com/oz/app", :post, apps.social)
    conn = put_req_header(conn(:post, "http://example.com/"), "host", "example.com")
    options = %{encryption_password: password, load_app_fn: fn id -> apps[String.to_atom(id)] end}
    ticket = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/app", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.App.call(options)
             |> Map.get(:resp_body)
             |> decode()

    [conn: conn, apps: apps, encryption_password: password, options: options, app_ticket: ticket]
  end

  describe "call/2" do
    test "allows null payload", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn _id -> apps.social end}
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)

      assert is_map Plug.Oz.Reissue.call(conn, options)
    end

    test "overrides defaults", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn _id -> apps.social end, ticket: %{ttl: :timer.minutes(10), iron: Iron.defaults()}, hawk: %{}}
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)

      assert is_map Plug.Oz.Reissue.call(conn, options)
    end

    test "reissues expired ticket", %{apps: apps, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn id -> apps[String.to_atom(id)] end, ticket: %{ttl: 5}}
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, apps.social)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.App.call(options)
               |> Map.get(:resp_body)
               |> decode()

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)

      Process.sleep(10)
      assert is_map Plug.Oz.Reissue.call(conn, options)
    end

    test "fails on app load error", %{app_ticket: app_ticket, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn _id -> {:error, "not found"} end}
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(options)
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid application\""}], "Invalid application"} == sent_resp(conn)
    end

    test "fails on missing app delegation rights", %{apps: %{social: social, network: %{id: id}}, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn _id -> social end, payload: %{issue_to: id}}
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(options)
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Application has no delegation rights\""}], "Application has no delegation rights"} == sent_resp(conn)
    end

    # test "fails on invalid reissue (request params)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
    #   options = %{encryption_password: password, load_app_fn: fn id -> apps[String.to_atom(id)] end, payload: %{issue_to: nil}}
    #   %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
    #   conn = conn
    #          |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
    #          |> put_req_header("authorization", header)

    #   assert Plug.Oz.reissue(conn, options) == {:error, "Invalid request payload: issueTo must be a string"}
    # end

    test "fails on invalid reissue (fails auth)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn id -> apps[String.to_atom(id)] end}
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(%{options | encryption_password: "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough_x"})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Bad hmac value\""}], "Bad hmac value"} == sent_resp(conn)
    end

    test "fails on invalid reissue (invalid app)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn id -> apps[String.to_atom(id)] end}
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(%{options | load_app_fn: fn _ -> nil end})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid application\""}], "Invalid application"} == sent_resp(conn)
    end

    test "fails on invalid reissue (missing grant)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn id -> apps[String.to_atom(id)] end}
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, options)
      options = Map.put(options, :load_grant_fn, fn _ -> %{grant: grant} end)

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.RSVP.call(Map.put(options, :rsvp, rsvp))
               |> Map.get(:resp_body)
               |> decode()

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(%{options | load_grant_fn: fn _ -> %{grant: nil} end})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid grant\""}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid reissue (grant error)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn id -> apps[String.to_atom(id)] end}
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, options)
      options = Map.put(options, :load_grant_fn, fn _ -> %{grant: grant} end)

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.RSVP.call(Map.put(options, :rsvp, rsvp))
               |> Map.get(:resp_body)
               |> decode()

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(%{options | load_grant_fn: fn _ -> {:error, "what?"} end})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid grant\""}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid reissue (grant user mismatch)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn id -> apps[String.to_atom(id)] end}
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, options)
      options = Map.put(options, :load_grant_fn, fn _ -> %{grant: grant} end)

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.RSVP.call(Map.put(options, :rsvp, rsvp))
               |> Map.get(:resp_body)
               |> decode()

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(%{options | load_grant_fn: fn _ -> %{grant: %{grant | user: "steve"}} end})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid grant\""}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid reissue (grant missing exp)", %{apps: apps, app_ticket: app_ticket, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn id -> apps[String.to_atom(id)] end}
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: app_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(apps.social, grant, password, options)
      options = Map.put(options, :load_grant_fn, fn _ -> %{grant: grant} end)

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, app_ticket)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.RSVP.call(Map.put(options, :rsvp, rsvp))
               |> Map.get(:resp_body)
               |> decode()

      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(%{options | load_grant_fn: fn _ -> Map.delete(grant, :exp) end})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid grant\""}], "Invalid grant"} == sent_resp(conn)
    end

    test "fails on invalid reissue (grant app does not match app or dlg)", %{conn: conn, encryption_password: password} do
      applications =  %{social: %{id: "social", key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256, delegate: true}, network: %{id: "network", key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}}
      options = %{encryption_password: password, load_app_fn: fn id -> applications[String.to_atom(id)] end}
      %{header: header} = Oz.Client.header("http://example.com/oz/app", :post, applications.social)

      # The app requests an app ticket using Oz.hawk authentication
      applications_ticket = conn
                            |> Plug.Adapters.Test.Conn.conn(:post, "/oz/app", [])
                            |> put_req_header("authorization", header)
                            |> Plug.Oz.App.call(options)
                            |> Map.get(:resp_body)
                            |> decode()

      # The user is redirected to the server, logs in, and grant app access, resulting in an rsvp
      grant = %{id: "a1b2c3d4e5f6g7h8i9j0", app: applications_ticket.app, user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}
      rsvp = Oz.Ticket.rsvp(applications.social, grant, password, [])

      # After granting app access, the user returns to the app with the rsvp
      options = Map.put(options, :load_grant_fn, fn _ -> %{grant: grant} end)

      # The app exchanges the rsvp for a ticket
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, applications_ticket)
      ticket = conn
               |> Plug.Adapters.Test.Conn.conn(:post, "/oz/rsvp", [])
               |> put_req_header("authorization", header)
               |> Plug.Oz.RSVP.call(Map.put(options, :rsvp, rsvp))
               |> Map.get(:resp_body)
               |> decode()

      # The app reissues the ticket with delegation to another app
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, ticket)
      delegated_ticket = conn
                         |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
                         |> put_req_header("authorization", header)
                         |> Plug.Oz.Reissue.call(Map.put(options, :payload, %{issue_to: applications.network.id}))
                         |> Map.get(:resp_body)
                         |> decode()

      # The other app reissues their ticket
      %{header: header} = Oz.Client.header("http://example.com/oz/reissue", :post, delegated_ticket)
      conn = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/reissue", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.Reissue.call(%{options | load_grant_fn: fn _ -> %{grant: %{grant | app: "xyz"}} end})
             |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Invalid grant\""}], "Invalid grant"} == sent_resp(conn)
    end
  end
end
