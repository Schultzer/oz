defmodule OzClientTest do
  use ExUnit.Case

  setup do
    app = %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: "sha256"}
    options = %{encryption_password: "passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword",
                load_app_fn: fn (_id) -> app end,
                ticket: %{ttl: 10 * 60 * 1000, iron: Iron.defaults()},
                hawk: %{}}
    [app: app, bypass: Bypass.open(), options: options, password: "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough"]
  end

  describe "header/3" do
    test "generates header" do
      app = %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256}
      assert Map.keys(Oz.Client.header("http://example.com/oz/app", :post, app)) == [:artifacts, :header]
    end
  end

  describe "connection/3" do
    test "obtains an application ticket and requests resource", %{app: app, bypass: bypass, options: options} do
      Bypass.expect_once bypass, "POST", "/oz/app", fn conn ->
        conn
        |> Plug.Oz.App.call(options)
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_status(200)
        |> Plug.Conn.send_resp()
      end
      Bypass.expect bypass, fn conn ->
        req = Hawk.Request.new(conn)
        Oz.Server.authenticate(req, options.encryption_password, options)
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, <<?", conn.method::binary(), ?\s, conn.request_path::binary(), ?">>)
      end

      client =  %{ticket: ticket1} = "http://localhost:#{bypass.port}" |> Oz.Client.new(app) |> Oz.Client.app("/")
      assert client.app_ticket == client.ticket
      assert client.result == "GET /"

      client = %{ticket: ticket2} = Oz.Client.request(client, "/resource")
      assert client.ticket == ticket1
      assert client.result == "GET /resource"

      Bypass.expect_once bypass, "POST", "/oz/reissue", fn conn ->
        conn
        |> Plug.Oz.Reissue.call(options)
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_status(200)
        |> Plug.Conn.send_resp()
      end
      client = %{ticket: ticket3} = Oz.Client.reissue(client)
      refute client.ticket == ticket2

      client = Oz.Client.request(client, "/resource")
      assert client.ticket == ticket3
      assert client.result == "GET /resource"
    end

    # test "errors on payload read fail", %{bypass: bypass}  do
    #   Bypass.expect_once bypass, "GET", "/", fn conn ->
    #     assert conn.query_string == ""
    #     Plug.Conn.send_resp(conn, 200, ~s({"access_token":"test1234"}))
    #   end
    #   client =  %{ticket: ticket1} = "http://localhost:#{bypass.port}" |> Oz.Client.new(app) |> Oz.Client.app("/")

    #   assert _requestAppTicket(client) == {:error, "error"}
    # end

    # test "errors on invalid app response", %{bypass: bypass, options: options, app: app} do
    #   Bypass.expect_once bypass, "POST", "/oz/app", fn conn ->
    #     raise payload = Plug.Oz.App.call(conn, options)
    #     conn
    #     |> Plug.Conn.put_resp_content_type("application/json")
    #     |> Plug.Conn.send_resp(400, Jason.encode!(payload))
    #   end
    #   client = "http://localhost:#{bypass.port}" |> Oz.Client.new(app) |> Oz.Client.app("/")

    #   # assert Oz.Client.app(client, "/") == {:error, "error"}
    # end
  end

  describe "request/3" do
    test "automatically refreshes ticket", %{app: app, bypass: bypass, options: options} do
      options = Deep.merge(options, %{ticket: %{ttl: 20}})
      Bypass.expect bypass, "POST", "/oz/app", fn conn ->
        conn
        |> Plug.Oz.App.call(options)
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_status(200)
        |> Plug.Conn.send_resp()
      end
      Bypass.expect bypass, "POST", "/oz/reissue", fn conn ->
        conn
        |> Plug.Oz.Reissue.call(options)
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_status(200)
        |> Plug.Conn.send_resp()
      end
      Bypass.expect bypass, fn conn ->
        case Oz.Server.authenticate(Hawk.Request.new(conn), options.encryption_password, options) do
          {:error, {status, msg}} ->
            Plug.Conn.send_resp(conn, status, <<?", msg::binary(), ?">>)

          {:error, {status, msg, {header, value}}} ->
            conn
            |> Plug.Conn.put_resp_header(header, value)
            |> Plug.Conn.send_resp(status, <<?", msg::binary(), ?">>)

          {:ok, _} ->
            conn
            |> Plug.Conn.put_resp_content_type("application/json")
            |> Plug.Conn.send_resp(200, <<?", conn.method::binary(), ?\s, conn.request_path::binary(), ?">>)
        end
      end

      client =  %{ticket: ticket1} = "http://localhost:#{bypass.port}" |> Oz.Client.new(app) |> Oz.Client.app("/")
      assert client.app_ticket == client.ticket
      assert client.result == "GET /"

      Process.sleep(30)
      client = Oz.Client.request(client, "/resource", method: :post)
      # IO.inspect client
      # IO.inspect ticket1
      # IO.inspect client.ticket

      assert client.result == "POST /resource"
      assert client.ticket !== ticket1
    end

    # test "errors on socket fail", %{password: password, bypass: bypass} do
    #   client = Oz.Client.new("http://localhost:#{bypass.port}/")
    #   Bypass.expect_once bypass, "GET", "/", fn conn ->
    #     assert conn.query_string == ""
    #     Plug.Conn.send_resp(conn, 200, ~s({"access_token":"test1234"}))
    #   end
    # end

    # test "errors on reissue fail", %{password: password, bypass: bypass} do
    #   client = Oz.Client.new("http://localhost:#{bypass.port}/")
    #   Bypass.expect_once bypass, "GET", "/", fn conn ->
    #     assert conn.query_string == ""
    #     Plug.Conn.send_resp(conn, 200, ~s({"access_token":"test1234"}))
    #   end
    # end

    test "does not reissue a 401 without payload", %{app: app, bypass: bypass, options: options} do
      Bypass.expect_once bypass, "POST", "/oz/app", fn conn ->
        conn
        |> Plug.Oz.App.call(options)
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_status(200)
        |> Plug.Conn.send_resp()
      end
      Bypass.expect bypass, "POST", "/oz/reissue", fn conn ->
        conn
        |> Plug.Oz.Reissue.call(options)
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_status(200)
        |> Plug.Conn.send_resp()
      end
      Bypass.expect bypass, "GET", "/", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(401, "\"\"")
      end
      client = "http://localhost:#{bypass.port}" |> Oz.Client.new(app) |> Oz.Client.app("/")
      assert client.result == ""
    end
  end

  describe "app/2" do
    test "reuses application ticket", %{app: app, bypass: bypass, options: options} do
      Bypass.expect_once bypass, "POST", "/oz/app", fn conn ->
        conn
        |> Plug.Oz.App.call(options)
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_status(200)
        |> Plug.Conn.send_resp()
      end
      Bypass.expect bypass, fn conn ->
        req = Hawk.Request.new(conn)
        Oz.Server.authenticate(req, options.encryption_password, options)
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, <<?", conn.method::binary(), ?\s, conn.request_path::binary(), ?">>)
      end
      client = %{ticket: ticket} = "http://localhost:#{bypass.port}" |> Oz.Client.new(app) |> Oz.Client.app("/")
      assert client.app_ticket == client.ticket
      assert client.result == "GET /"

      client = Oz.Client.app(client, "/resource")
      assert client.ticket == ticket
      assert client.result == "GET /resource"
    end

    test "handles app ticket request errors", %{app: app, bypass: bypass} do
      Bypass.expect bypass, fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(400, "error")
      end

      assert {:error, {500, "Client registration failed with unexpected response"}} == "http://localhost:#{bypass.port}" |> Oz.Client.new(app) |> Oz.Client.app("/")
    end
  end

  describe "reissue/4" do
    test "errors on non 200 reissue response", %{app: app, bypass: bypass, options: options} do
      Bypass.expect_once bypass, "POST", "/oz/app", fn conn ->
        conn
        |> Plug.Oz.App.call(options)
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_status(200)
        |> Plug.Conn.send_resp()
      end
      Bypass.expect_once bypass, "GET", "/", fn conn ->
        req = Hawk.Request.new(conn)
        Oz.Server.authenticate(req, options.encryption_password, options)
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, <<?", conn.method::binary(), ?\s, conn.request_path::binary(), ?">>)
      end
      Bypass.expect bypass, fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(400, "\"error\"")
      end

      client = "http://localhost:#{bypass.port}" |> Oz.Client.new(app) |> Oz.Client.app("/")
      assert client.app_ticket == client.ticket
      assert client.result == "GET /"
      assert {:error, {500, "error"}} == Oz.Client.reissue(client)
    end
  end

  # describe "_request/4" do
  #   test "errors on payload read fail", %{password: password, bypass: bypass} do
  #     client = Oz.Client.new("http://localhost:#{bypass.port}/")
  #     Bypass.expect_once bypass, "GET", "/", fn conn ->
  #       assert conn.query_string == ""
  #       Plug.Conn.send_resp(conn, 200, ~s({"access_token":"test1234"}))
  #     end
  #   end
  # end

  # describe "_request_app_ticket/4" do
  #   test "errors on socket fail", %{password: password, bypass: bypass} do
  #     client = Oz.Client.new("http://localhost:#{bypass.port}/")
  #     Bypass.expect_once bypass, "GET", "/", fn conn ->
  #       assert conn.query_string == ""
  #       Plug.Conn.send_resp(conn, 200, ~s({"access_token":"test1234"}))
  #     end
  #   end

  #   test "errors on redirection", %{password: password, bypass: bypass} do
  #     client = Oz.Client.new("http://localhost:#{bypass.port}/")
  #     Bypass.expect_once bypass, "GET", "/", fn conn ->
  #       assert conn.query_string == ""
  #       Plug.Conn.send_resp(conn, 200, ~s({"access_token":"test1234"}))
  #     end
  #   end
  # end
end
