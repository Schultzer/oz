defmodule PlugOzAppTest do
  use ExUnit.Case
  use Plug.Test

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

    [conn: conn, apps: apps, encryption_password: password, options: options, app_ticket: ticket]
  end

  describe "call/2" do
    test "overrides defaults", %{apps: %{social: social}, conn: conn, encryption_password: password} do
      options = %{encryption_password: password, load_app_fn: fn _id -> social end, ticket: %{ttl: :timer.minutes(10), iron: Iron.defaults(), hawk: %{}}}
      %{header: header} = Oz.Client.header("http://example.com/oz/app", :post, social)
      conn = conn
            |> Plug.Adapters.Test.Conn.conn(:post, "/oz/app", [])
            |> put_req_header("authorization", header)
            |> Plug.Oz.App.call(options)

      refute conn.halted
    end

    test "fails on invalid app request (bad credentials)", %{apps: %{network: network, social: social}, conn: conn, encryption_password: password} do
      %{header: header} = Oz.Client.header("http://example.com/oz/app", :post, social)
      conn = conn
            |> Plug.Adapters.Test.Conn.conn(:post, "/oz/app", [])
            |> put_req_header("authorization", header)
            |> Plug.Oz.App.call(%{encryption_password: password, load_app_fn: fn _id -> network end})
            |> Plug.Conn.send_resp()

      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Bad mac\""}], "Bad mac"} == sent_resp(conn)
    end
  end
end
