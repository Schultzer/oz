defmodule OzTicketTest do
  use ExUnit.Case

  setup do
    [
      password: "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough",
    ]
  end

  describe "issue/3" do
    test "should construct a valid ticket", %{password: password} do
      app = %{id: "123", scope: ["a", "b"]}
      grant = %{id: "s81u29n1812", user: "456", exp: Hawk.Now.msec() + 5000, scope: ["a"]}
      envelope = Oz.Ticket.issue(app, grant, password, %{ttl: 10 * 60 * 1000, ext: %{public: %{x: "welcome"}, private: %{x: 123}}})
      assert envelope[:ext] == %{x: "welcome"}
      assert envelope[:exp] == grant.exp
      assert envelope[:scope] == ["a"]
      ticket = Oz.Ticket.parse(envelope.id, password)
      assert ticket[:ext] == %{private: %{x: 123}, public: %{x: "welcome"}}
      envelope2 = Oz.Ticket.reissue(ticket, grant, password, [])
      assert envelope2.ext == %{x: "welcome"}
      assert envelope2.id !== envelope.id
    end

    test "errors on invalid grant (scope outside app)", %{password: password} do
      assert Oz.Ticket.issue(%{id: "abc", scope: ["a"]}, %{id: "123", user: "steve", exp: 1442690715989, scope: ["b"]}, password, []) == {:error, {500, "Grant scope is not a subset of the application scope"}}
    end

    test "errors on invalid app scope", %{password: password} do
      assert Oz.Ticket.issue(%{id: "abc", scope: "a"}, %{id: "123", user: "steve", exp: 1442690715989, scope: 'b'}, password, []) == {:error, {400, "Scope includes 98"}}
    end
  end

  describe "reissue/3" do
    test "sets delegate to false", %{password: password} do
      envelope = Oz.Ticket.issue(%{id: "123"}, password, [])
      ticket = Oz.Ticket.parse(envelope.id, password)
      envelope2 = Oz.Ticket.reissue(ticket, password, %{issue_to: "345", delegate: false})
      assert envelope2.delegate == false
    end

    test "errors on issue_to when delegate is not allowed", %{password: password} do
      envelope = Oz.Ticket.issue(%{id: "123"}, password, %{delegate: false})
      assert envelope.delegate == false
      ticket = Oz.Ticket.parse(envelope.id, password)
      assert {:error, {403, "Ticket does not allow delegation"}} == Oz.Ticket.reissue(ticket, password, %{issue_to: "345"})
    end

    test "errors on delegate override", %{password: password} do
      envelope = Oz.Ticket.issue(%{id: "123"}, password, %{delegate: false})
      assert envelope.delegate == false
      ticket = Oz.Ticket.parse(envelope.id, password)
      assert {:error, {403, "Cannot override ticket delegate restriction"}} == Oz.Ticket.reissue(ticket, password, %{delegate: true})
    end

    test "errors on missing parent scope", %{password: password} do
      assert Oz.Ticket.reissue(%{grant: "321", scope: []}, %{id: "321"}, password, %{scope: ["a"]}) == {:error, {403, "New scope is not a subset of the parent ticket scope"}}
    end

    test "errors on invalid options scope", %{password: password} do
      assert Oz.Ticket.reissue(%{grant: "123", scope: ["a"]}, %{id: "123"}, password, %{scope: 'a'}) == {:error, {403, "New scope is not a subset of the parent ticket scope"}}
    end

    test "errors on options.issueTo and ticket.dlg conflict", %{password: password} do
      assert Oz.Ticket.reissue(%{dlg: "123"}, %{id: "321"}, password, %{issue_to: "345"}) == {:error, {400, "Cannot re-delegate"}}
    end

    test "errors on mismatching grants (different)", %{password: password} do
      envelope = Oz.Ticket.issue(%{id: "123"}, password, [])
      assert Oz.Ticket.reissue(Map.put(envelope, :grant, "234"), %{id: "123", user: "steve", exp: 1442690715989}, password, issue_to: "321") == {:error, {500, "Parent ticket grant does not match options.grant"}}
    end
  end

  describe "rsvp/3" do
    test "constructs a valid rsvp", %{password: password} do
      envelope = Oz.Ticket.rsvp(%{id: "123"}, %{id: "s81u29n1812"}, password)
      result = Oz.Ticket.parse(envelope, password)
      assert result.app == "123"
      assert result.grant == "s81u29n1812"
    end
  end

  describe "generate/2" do
    test "generates a ticket with only public ext", %{password: password} do
      ticket = Oz.Ticket.generate(%{}, password, %{ext: %{public: %{x: 1 }}})
      assert ticket.ext.x == 1
    end

    test "generates a ticket with only private ext", %{password: password} do
      ticket = Oz.Ticket.generate(%{}, password, %{ext: %{private: %{x: 1 }}})
      assert is_nil ticket[:ext]
    end

    test "overrides hawk options", %{password: password} do
      ticket = Oz.Ticket.generate(%{}, password, %{key_bytes: 10, hmac_algorithm: "something"})
      assert byte_size(ticket.key) == 10
      assert ticket.algorithm == "something"
    end
  end

  describe "parse/4" do
    test "errors on wrong password", %{password: password} do
      envelope = Oz.Ticket.issue(%{id: "123"}, %{id: "s81u29n1812", user: "456", exp: Hawk.Now.msec() + 5000, scope: ["a", "b"]}, password, %{ttl: 10 * 60 * 1000})
      assert {:error, {401, "Bad hmac value", {"www-authenticate", "Hawk error=\"Bad hmac value\""}}} == Oz.Ticket.parse(envelope.id, "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough_x")
    end
  end
end
