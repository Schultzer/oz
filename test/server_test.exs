defmodule OzServerTest do
  use ExUnit.Case
  use Plug.Test

  setup do
    Application.put_env(:plug, :validate_header_keys_during_test, true)
    [
      conn: put_req_header(conn(:post, "http://example.com/oz/rsvp"), "host", "example.com"),
      app: %{id: "123"},
      grant: %{id: "s81u29n1812", user: "456", exp: 5000, scope: ["a", "b"]},
      password: "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough"]
  end

  describe "authenticate/3" do
    # test "throws an error on missing password"do
    #   assert Oz.Server.authenticate(nil, nil) == {:error, "invalid encryption password"}
    # end

    test "authenticates a request", %{conn: conn, app: app, grant: grant, password: password} do
      envelope = Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() + &1)), password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      req = conn |> put_req_header("authorization", header) |> Hawk.Request.new()
      assert {:ok, _} = Oz.Server.authenticate(req, password)
    end

    test "authenticates a request (hawk options)", %{conn: conn, app: app, grant: grant, password: password}  do
      envelope = Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() + &1)), password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      req = conn |> put_req_header("authorization", header) |> Hawk.Request.new()
      assert {:ok, _} = Oz.Server.authenticate(req, password, %{hawk: %{host_header_name: "hostx1"}})
    end

    test "fails to authenticate a request with bad password", %{conn: conn, app: app, grant: grant, password: password} do
      envelope = Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() + &1)), password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      req = conn |> put_req_header("authorization", header) |> Hawk.Request.new()
      assert {:error, {401, "Bad hmac value", {"www-authenticate", "Hawk error=\"Bad hmac value\""}}} == Oz.Server.authenticate(req, "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough_x")
    end

    test "fails to authenticate a request with expired ticket", %{conn: conn, app: app, grant: grant, password: password} do
      envelope = Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() - &1)), password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      req = conn |> put_req_header("authorization", header) |> Hawk.Request.new()
      assert {:error, {401, "Expired ticket", {"www-authenticate", "Hawk error=\"Expired ticket\""}}} == Oz.Server.authenticate(req, password)
    end

    test "fails to authenticate a request with mismatching app id", %{conn: conn, app: app, grant: grant, password: password} do
      envelope = %{Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() + &1)), password, []) | app: "567"}
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      req = conn |> put_req_header("authorization", header) |> Hawk.Request.new()
      assert {:error, {401, "Mismatching application id", {"www-authenticate", "Hawk error=\"Mismatching application id\""}}} == Oz.Server.authenticate(req, password)
    end

    test "fails to authenticate a request with mismatching dlg id", %{conn: conn, app: app, grant: grant, password: password} do
      envelope = Map.put(Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() + &1)), password, []), :dlg, "567")
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      req = conn |> put_req_header("authorization", header) |> Hawk.Request.new()
      assert {:error, {401, "Mismatching delegated application id", {"www-authenticate", "Hawk error=\"Mismatching delegated application id\""}}} == Oz.Server.authenticate(req, password)
    end
  end
end
