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
      options = %{ttl: 10 * 60 * 1000, ext: %{public: %{x: "welcome"}, private: %{x: 123}}}
      envelope = Oz.Ticket.issue(app, grant, password, options)
      assert envelope[:ext] == %{x: "welcome"}
      assert envelope[:exp] == grant.exp
      assert envelope[:scope] == ["a"]
      ticket = Oz.Ticket.parse(envelope.id, password)
      assert ticket[:ext] == %{private: %{x: 123}, public: %{x: "welcome"}}
      envelope2 = Oz.Ticket.reissue(ticket, grant, password, [])
      assert envelope2.ext == %{x: "welcome"}
      assert envelope2.id !== envelope.id
    end

    # test "errors on missing app", %{password: password} do
    #   assert Oz.Ticket.issue(%{app: nil, nil, password) == {:error, "invalid application"}
    # end

    # test "errors on invalid app", %{password: password} do
    #   assert Oz.Ticket.issue(%{}, nil, password) == {:error, "invalid application"}
    # end

    # test "errors on invalid grant (missing id)", %{password: password} do
    #   assert Oz.Ticket.issue(%{id: "abc"}, %{}, password) == {:error, "invalid grant"}
    # end

    # test "errors on invalid grant (missing user)", %{password: password} do
    #   assert Oz.Ticket.issue(%{id: "abc"}, %{id: "123"}, password) == {:error, "invalid grant"}
    # end

    # test "errors on invalid grant (missing exp)", %{password: password} do
    #   assert Oz.Ticket.issue(%{id: "abc"}, %{id: "123", user: "steve"}, password) == {:error, "invalid grant"}
    # end

    # test "errors on invalid grant (scope outside app)", %{password: password} do
    #   assert Oz.Ticket.issue(%{id: "abc", scope: ["a"]}, %{id: "123", user: "steve", exp: 1442690715989, scope: ["b"]}, password) == {:error, "grant scope is not a subset of the application scope"}
    # end

    # test "errors on invalid app scope", %{password: password} do
    #   assert Oz.Ticket.issue(%{id: "abc", scope: "a"}, nil, password) == {:error, "scope not instance of Array"}
    # end

    # test "errors on invalid password", %{password: password} do
    #   assert Oz.Ticket.issue(%{id: "abc"}, nil, '') == {:error, "invalid encryption password"}
    # end
  end

  describe "reissue/3" do
    test "sets delegate to false", %{password: password} do
      envelope = Oz.Ticket.issue(%{id: "123"}, password, [])
      ticket = Oz.Ticket.parse(envelope.id, password)
      envelope2 = Oz.Ticket.reissue(%{ticket: ticket}, password, %{issue_to: "345", delegate: false})
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

    # test "errors on missing parent ticket", %{password: password} do
    #   assert Oz.Ticket.reissue(nil, nil, '') == {:error, "invalid parent ticket"}
    # end

    # test "errors on missing password" do
    #   assert Oz.Ticket.reissue(%{}, nil, '') == {:error, "invalid encryption password"}
    # end

    # test "errors on missing parent scope", %{password: password} do
    #   assert Oz.Ticket.reissue(%{}, nil, password, %{scope: ["a"]}) == {:error, "new scope is not a subset of the parent ticket scope"}
    # end

    # test "errors on invalid parent scope", %{password: password} do
    #   assert Oz.Ticket.reissue(%{scope: "a"}, nil, password, %{scope: ["a"]}) == {:error, "scope not instance of Array"}
    # end

    # test "errors on invalid options scope", %{password: password} do
    #   assert Oz.Ticket.reissue(%{scope: ["a"]}, nil, password, %{scope: "a"}) == {:error, "scope not instance of Array"}
    # end

    # test "errors on invalid grant (missing id)", %{password: password} do
    #   assert Oz.Ticket.reissue(%{}, %{}, password) == {:error, "invalid grant"}
    # end

    # test "errors on invalid grant (missing user)", %{password: password} do
    #   assert Oz.Ticket.reissue(%{}, %{id: "abc"}, password) == {:error, "invalid grant"}
    # end

    # test "errors on invalid grant (missing exp)", %{password: password} do
    #   assert Oz.Ticket.reissue(%{}, %{id: "abc", user: "steve"}, password) == {:error, "invalid grant"}
    # end

    # test "errors on options.issueTo and ticket.dlg conflict", %{password: password} do
    #   assert Oz.Ticket.reissue(%{dlg: "123"}, nil, password, %{issue_to: "345"}) == {:error, "cannot re-delegate"}
    # end

    # test "errors on mismatching grants (missing grant)", %{password: password} do
    #   assert Oz.Ticket.reissue(%{grant: "123"}, nil, password) == {:error, "parent ticket grant does not match options.grant"}
    # end

    # test "errors on mismatching grants (missing parent)", %{password: password} do
    #   assert Oz.Ticket.reissue(%{}, %{id: 123, user: "steve", exp: 1442690715989}, password) == {:error, "parent ticket grant does not match options.grant"}
    # end

    # test "errors on mismatching grants (different)", %{password: password} do
    #   assert Oz.Ticket.reissue(%{grant: "234"}, %{id: 123, user: "steve", exp: 1442690715989}, password) == {:error, "parent ticket grant does not match options.grant"}
    # end
  end

  describe "rsvp/3" do
    # test "errors on missing app", %{password: password} do
    #   assert Oz.Ticket.issue(nil, %{id: "123"}, password) == {:error, "invalid application"}
    # end

    # test "errors on invalid app", %{password: password} do
    #   assert Oz.Ticket.issue(%{}, %{id: "123"}, password) == {:error, "invalid application"}
    # end

    # test "errors on missing grant", %{password: password} do
    #   assert Oz.Ticket.rsvp(%{}, %{id: "123"}, password) == {:error, "invalid application"}
    # end

    # test "errors on invalid grant", %{password: password} do
    #   assert Oz.Ticket.rsvp(%{id: "123"}, nil, password) == {:error, "invalid grant"}
    # end

    # test "errors on missing password", %{password: password} do
    #   assert Oz.Ticket.rsvp(%{id: "123"}, %{}, password) == {:error, "invalid grant"}
    # end

    test "constructs a valid rsvp", %{password: password} do
      envelope = Oz.Ticket.rsvp(%{id: "123"}, %{id: "s81u29n1812"}, password)
      result = Oz.Ticket.parse(envelope, password)
      assert result.app == "123"
      assert result.grant == "s81u29n1812"
    end

    # test "fails to construct a valid rsvp due to bad Iron options", %{password: password} do
    #   assert Oz.Ticket.rsvp(%{app: %{id: "123"}, grant: %{id: "s81u29n1812"}}, password, %{iron: %{Iron.defaults | encryption: nil}}) == {:error, "bad options"}
    # end
  end

  describe "generate/2" do
    # test "errors on random fail", %{password: password} do
    #   # Maybe a mock maby not :)
    #   # const orig = Cryptiles.randomString;
    #   # Cryptiles.randomString = function (size) {

    #   #     Cryptiles.randomString = orig;
    #   #     throw new Error('fake');
    #   # };
    #   assert Oz.Ticket.generate(%{}, password) == {:error, "fake"}
    # end

    # test "errors on missing password" do
    #   assert Oz.Ticket.generate(%{}, "") == {:error, "empty password"}
    # end

    test "generates a ticket with only public ext", %{password: password} do
      ticket = Oz.Ticket.generate(%{}, password, %{ext: %{public: %{x: 1 }}})
      assert ticket.ext.x == 1
    end

    test "generates a ticket with only private ext", %{password: password} do
      ticket = Oz.Ticket.generate(%{}, password, %{ext: %{private: %{x: 1 }}})
      assert is_nil ticket[:ext]
    end

    test "overrides hawk options", %{password: password} do
      input = %{}
      ticket = Oz.Ticket.generate(input, password, %{key_bytes: 10, hmac_algorithm: "something"})
      assert byte_size(ticket.key) == 10
      assert ticket.algorithm == "something"
    end
  end

  describe "parse/4" do
    test "errors on wrong password", %{password: password} do
      envelope = Oz.Ticket.issue(%{id: "123"}, %{id: "s81u29n1812", user: "456", exp: Hawk.Now.msec() + 5000, scope: ["a", "b"]}, password, %{ttl: 10 * 60 * 1000})
      assert {:error, {401, "Bad hmac value", {"www-authenticate", "Hawk error=\"Bad hmac value\""}}} == Oz.Ticket.parse(envelope.id, "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough_x")
    end

    # test "errors on missing password", %{password: password} do
    #   assert Oz.Ticket.parse("abc", '') == {:error, "invalid encryption password"}
    # end
  end
end
