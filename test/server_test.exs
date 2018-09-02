defmodule OzServerTest do
  use ExUnit.Case

  setup do
    [
      req: %{authorization: [], content_type: "", host: "example.com", method: "POST", port: 80, url: "/oz/rsvp"},
      app: %{id: "123"},
      grant: %{id: "s81u29n1812", user: "456", exp: 5000, scope: ["a", "b"]},
      password: "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough"]
  end

  describe "authenticate/3" do
    test "authenticates a request", %{req: req, app: app, grant: grant, password: password} do
      envelope = Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() + &1)), password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      assert {:ok, _} = Oz.Server.authenticate(%{req | authorization: header}, password)
    end

    test "authenticates a request (hawk options)", %{req: req, app: app, grant: grant, password: password}  do
      envelope = Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() + &1)), password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      assert {:ok, _} = Oz.Server.authenticate(%{req | authorization: header}, password, %{hawk: %{host_header_name: "hostx1"}})
    end

    test "fails to authenticate a request with bad password", %{req: req, app: app, grant: grant, password: password} do
      envelope = Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() + &1)), password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      assert {:error, {401, "Bad hmac value", {"www-authenticate", "Hawk error=\"Bad hmac value\""}}} == Oz.Server.authenticate(%{req | authorization: header}, "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough_x")
    end

    test "fails to authenticate a request with expired ticket", %{req: req, app: app, grant: grant, password: password} do
      envelope = Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() - &1)), password, [])
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      assert {:error, {401, "Expired ticket", {"www-authenticate", "Hawk error=\"Expired ticket\""}}} == Oz.Server.authenticate(%{req | authorization: header}, password)
    end

    test "fails to authenticate a request with mismatching app id", %{req: req, app: app, grant: grant, password: password} do
      envelope = %{Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() + &1)), password, []) | app: "567"}
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      assert {:error, {401, "Mismatching application id", {"www-authenticate", "Hawk error=\"Mismatching application id\""}}} == Oz.Server.authenticate(%{req | authorization: header}, password)
    end

    test "fails to authenticate a request with mismatching dlg id", %{req: req, app: app, grant: grant, password: password} do
      envelope = Map.put(Oz.Ticket.issue(app, Map.update!(grant, :exp, &(Hawk.Now.msec() + &1)), password, []), :dlg, "567")
      %{header: header} = Oz.Client.header("http://example.com/oz/rsvp", :post, envelope)
      assert {:error, {401, "Mismatching delegated application id", {"www-authenticate", "Hawk error=\"Mismatching delegated application id\""}}} == Oz.Server.authenticate(%{req | authorization: header}, password)
    end
  end
end
