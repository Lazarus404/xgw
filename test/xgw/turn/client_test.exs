defmodule XGW.TURN.ClientTest do
  use ExUnit.Case, async: true
  doctest XGW.TURN.Client

  alias XGW.TURN.Client
  alias XGW.Test.TurnFixtures
  alias XMediaLib.Stun

  test "parse_turn_server resolves host and default port" do
    assert {:ok, {{127, 0, 0, 1}, 3478}} = Client.parse_turn_server("turn:127.0.0.1")
    assert {:ok, {{127, 0, 0, 1}, 9999}} = Client.parse_turn_server("turn:127.0.0.1:9999")
    assert {:error, :unsupported_turns} = Client.parse_turn_server("turns:127.0.0.1:5349")
  end

  test "rest_credentials matches coturn REST format" do
    secret = "test-secret"
    {username, password} = Client.rest_credentials("alice", secret, 3600)

    assert username =~ ":alice"
    assert is_binary(password)
    assert password == Base.encode64(:crypto.mac(:hmac, :sha, secret, username))
  end

  test "long_term_key is MD5 username:realm:password" do
    key = Client.long_term_key("user", "realm", "pass")
    assert key == :crypto.hash(:md5, "user:realm:pass")
  end

  test "allocate handles unauthenticated success" do
    wire = TurnFixtures.allocate_success_wire()

    send_recv = fn _req, _endpoint -> {:ok, wire} end

    assert {:ok, allocation} =
             Client.allocate(send_recv, {{127, 0, 0, 1}, 3478}, [])

    assert allocation.relay == {{203, 0, 113, 99}, 49_999}
    assert allocation.lifetime_s > 0
  end

  test "allocate handles 401 challenge then success" do
    challenge = TurnFixtures.allocate_challenge_wire(realm: "xgw.test", nonce: "n1")
    success = TurnFixtures.allocate_success_wire()
    {:ok, step} = Agent.start_link(fn -> 0 end)

    send_recv = fn _req, _endpoint ->
      n = Agent.get_and_update(step, fn s -> {s, s + 1} end)
      if n == 0, do: {:ok, challenge}, else: {:ok, success}
    end

    cred_opts = [turn_username: "user", turn_password: "pass"]

    assert {:ok, allocation} =
             Client.allocate(send_recv, {{127, 0, 0, 1}, 3478}, cred_opts)

    assert allocation.relay == {{203, 0, 113, 99}, 49_999}
    assert allocation.realm == "xgw.test"
    Agent.stop(step)
  end

  test "delete sends refresh with lifetime 0" do
    success = Stun.encode(TurnFixtures.refresh_success(0))

    send_recv = fn req, _endpoint ->
      assert {:ok, %Stun{method: :refresh, attrs: %{lifetime: <<0::32>>}}} = Stun.decode(req)
      {:ok, success}
    end

    allocation = %{
      turn_server: {{127, 0, 0, 1}, 3478},
      relay: {{203, 0, 113, 1}, 50_000},
      lifetime_s: 600,
      username: "user",
      realm: "realm",
      nonce: "nonce",
      integrity_key: <<>>
    }

    assert :ok = Client.delete(send_recv, allocation)
  end

  test "create_permission encodes createperm with xor peer address" do
    wire =
      Client.create_permission_request(%{
        turn_server: {{127, 0, 0, 1}, 3478},
        relay: {{203, 0, 113, 1}, 50_000},
        lifetime_s: 600,
        username: "user",
        realm: "realm",
        nonce: "nonce",
        integrity_key: <<>>
      }, {{8, 8, 8, 8}, 3478})

    assert {:ok, %Stun{method: :createperm, attrs: attrs}} = Stun.decode(wire)
    assert attrs.xor_peer_address == {{8, 8, 8, 8}, 3478}
  end

  test "send_indication encodes send indication with data" do
    allocation = %{
      turn_server: {{127, 0, 0, 1}, 3478},
      relay: {{203, 0, 113, 1}, 50_000},
      lifetime_s: 600,
      username: "",
      realm: "",
      nonce: "",
      integrity_key: <<>>
    }

    wire = Client.send_indication(allocation, {{1, 2, 3, 4}, 5678}, "stun-payload")
    assert {:ok, %Stun{class: :indication, method: :send, attrs: attrs}} = Stun.decode(wire)
    assert attrs.data == "stun-payload"
    assert attrs.xor_peer_address == {{1, 2, 3, 4}, 5678}
  end

  test "encode_channel_data / decode_channel_data round-trip with padding" do
    channel = 0x4000
    app = "abc"

    wire = Client.encode_channel_data(channel, app)
    assert byte_size(wire) == 8
    assert {:ok, ^channel, ^app} = Client.decode_channel_data(wire)
  end

  test "decode_channel_data rejects truncated and out-of-range channel" do
    assert :error = Client.decode_channel_data(<<0x40, 0x00, 0, 5, "hi">>)
    assert :error = Client.decode_channel_data(<<0x3F, 0xFF, 0, 1, "x", 0, 0, 0>>)
    assert :error = Client.decode_channel_data(<<>>)
  end

  test "channel_bind_request encodes channelbind with peer and channel number" do
    allocation = sample_allocation()

    wire = Client.channel_bind_request(allocation, {{8, 8, 8, 8}, 3478}, 0x4001)
    assert {:ok, %Stun{method: :channelbind, attrs: attrs}} = Stun.decode(wire)
    assert attrs.xor_peer_address == {{8, 8, 8, 8}, 3478}
    assert attrs.channel_number == <<0x4001::16, 0::16>>
  end

  test "channel_bind succeeds on channelbind success response" do
    allocation = sample_allocation()

    send_recv = fn req, _endpoint ->
      assert {:ok, %Stun{method: :channelbind, class: :request}} = Stun.decode(req)
      {:ok, Stun.encode(TurnFixtures.channel_bind_success())}
    end

    assert :ok = Client.channel_bind(send_recv, allocation, {{1, 2, 3, 4}, 9}, 0x4000)
  end

  defp sample_allocation do
    %{
      turn_server: {{127, 0, 0, 1}, 3478},
      relay: {{203, 0, 113, 1}, 50_000},
      lifetime_s: 600,
      username: "user",
      realm: "realm",
      nonce: "nonce",
      integrity_key: <<>>
    }
  end
end
