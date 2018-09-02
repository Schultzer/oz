defmodule PlugOzAppTest do
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

  defmodule ConfigFail do
    use Oz.Config

    def get_credentials(_id, _opts) do
      %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}
    end

    def get_app(id), do: get_credentials(id, %{})

    def get_grant(_id) do
      %{grant: %{id: "a1b2c3d4e5f6g7h8i9j0", app: "social", user: "john", exp: Hawk.Now.msec() + :timer.minutes(1)}, ext: %{}}
    end
  end

  setup do
    Application.put_env(:plug, :validate_header_keys_during_test, true)

    password = "a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough"
    apps = %{social: %{id: "social", scope: ["a", "b", "c"], key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", algorithm: :sha256},
             network: %{id: "network", scope: ["b", "x"], key: "witf745itwn7ey4otnw7eyi4t7syeir7bytise7rbyi", algorithm: :sha256}}
    %{header: header} = Oz.Client.header("http://example.com/oz/app", :post, apps.social)
    conn = put_req_header(conn(:post, "http://example.com/"), "host", "example.com")
    options = %{encryption_password: password, config: Config}
    ticket = conn
             |> Plug.Adapters.Test.Conn.conn(:post, "/oz/app", [])
             |> put_req_header("authorization", header)
             |> Plug.Oz.App.call(options)

    [conn: conn, apps: apps, encryption_password: password, options: options, app_ticket: ticket]
  end

  describe "call/2" do
    test "overrides defaults", %{apps: apps, conn: conn, encryption_password: password} do
      %{header: header} = Oz.Client.header("http://example.com/oz/app", :post, apps.social)
      conn = conn
            |> Plug.Adapters.Test.Conn.conn(:post, "/oz/app", [])
            |> put_req_header("authorization", header)
            |> Plug.Oz.App.call(encryption_password: password, config: Config, ticket: %{ttl: :timer.minutes(10), iron: Iron.defaults(), hawk: %{}})
            |> Plug.Conn.resp(200, "APP")
            |> Plug.Conn.send_resp()

      refute conn.halted
      assert_received {:plug_conn, :sent}
      assert {200, [{"cache-control", "max-age=0, private, must-revalidate"}, {"content-type", "application/json; charset=utf-8"}], "APP"} == sent_resp(conn)
    end

    test "fails on invalid app request (bad credentials)", %{apps: apps, conn: conn, encryption_password: password} do
      %{header: header} = Oz.Client.header("http://example.com/oz/app", :post, apps.social)
      conn = conn
            |> Plug.Adapters.Test.Conn.conn(:post, "/oz/app", [])
            |> put_req_header("authorization", header)
            |> Plug.Oz.App.call(%{encryption_password: password, config: ConfigFail})
            |> Plug.Conn.send_resp()

      assert conn.halted
      assert_received {:plug_conn, :sent}
      assert {401, [{"cache-control", "max-age=0, private, must-revalidate"}, {"www-authenticate", "Hawk error=\"Bad mac\""}], "Bad mac"} == sent_resp(conn)
    end
  end
end
