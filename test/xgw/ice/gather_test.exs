defmodule XGW.ICE.GatherTest do
  use ExUnit.Case, async: true

  alias XGW.ICE
  alias XGW.ICE.Gather
  alias XGW.Test.{StunFixtures, TurnFixtures}

  test "host_addresses honors advertised_ip" do
    assert [{10, 0, 0, 1}] = Gather.host_addresses(advertised_ip: {10, 0, 0, 1}, include_loopback: false)
  end

  test "host_addresses honors advertised_ips over auto-detect" do
    ips = [{192, 0, 2, 1}, {192, 0, 2, 2}]

    assert ips ==
             Gather.host_addresses(
               advertised_ips: ips,
               include_loopback: false
             )
  end

  test "host_addresses auto-detect uses injectable getifaddrs" do
    fake_ifs = [
      {"lo0", [addr: {127, 0, 0, 1}]},
      {"en0", [addr: {192, 0, 2, 5}]}
    ]

    assert [{127, 0, 0, 1}, {192, 0, 2, 5}] =
             Gather.host_addresses(
               include_loopback: true,
               getifaddrs: fn -> {:ok, fake_ifs} end
             )
  end

  test "host_candidates assigns descending local preference per interface" do
    port = 50_000

    cands =
      Gather.host_candidates({{0, 0, 0, 0}, port},
        advertised_ips: [{127, 0, 0, 1}, {192, 0, 2, 1}],
        include_loopback: false
      )

    assert length(cands) == 2
    assert Enum.map(cands, & &1.priority) == Enum.sort(Enum.map(cands, & &1.priority), :desc)
    assert hd(cands).ip == "127.0.0.1"
    assert hd(cands).port == port
    assert hd(cands).type == "host"
  end

  test "foundation is stable for same type ip transport" do
    ip = {192, 0, 2, 1}
    a = ICE.foundation("host", ip, "udp")
    b = ICE.foundation("host", ip, "udp")
    assert a == b
    assert a != ICE.foundation("host", {192, 0, 2, 2}, "udp")
  end

  test "gather_host matches host_candidates" do
    sock = {{10, 1, 2, 3}, 9000}
    opts = [advertised_ip: {10, 1, 2, 3}, include_loopback: false]
    assert Gather.gather_host(sock, opts) == Gather.host_candidates(sock, opts)
  end

  test "parse_stun_server resolves host and default port" do
    assert {:ok, {{127, 0, 0, 1}, 3478}} = Gather.parse_stun_server("stun:127.0.0.1")
    assert {:ok, {{127, 0, 0, 1}, 9999}} = Gather.parse_stun_server("stun:127.0.0.1:9999")
    assert {:error, _} = Gather.parse_stun_server("turn:127.0.0.1:3478")
  end

  test "srflx priority is lower than linked host" do
    host =
      Gather.host_candidates({{0, 0, 0, 0}, 50_000},
        advertised_ip: {192, 0, 2, 1},
        include_loopback: false
      )
      |> hd()

    srflx = Gather.build_srflx({{203, 0, 113, 1}, 60_000}, host, ICE.local_preference_from_priority(host))
    assert srflx.foundation == host.foundation
    assert srflx.type == "srflx"
    assert srflx.priority < host.priority
    assert srflx.rest =~ "raddr #{host.ip} rport #{host.port}"
  end

  test "srflx_from_response uses xor_mapped_address" do
    host =
      Gather.host_candidates({{0, 0, 0, 0}, 50_000},
        advertised_ip: {192, 0, 2, 1},
        include_loopback: false
      )
      |> hd()

    stun = XGW.Test.StunFixtures.binding_success(xor_mapped_address: {{203, 0, 113, 50}, 54_321})
    assert {:ok, srflx} = Gather.srflx_from_response(stun, host)
    assert srflx.ip == "203.0.113.50"
    assert srflx.port == 54_321
  end

  test "query_srflx with injectable send_recv" do
    host =
      Gather.host_candidates({{0, 0, 0, 0}, 50_000},
        advertised_ip: {192, 0, 2, 1},
        include_loopback: false
      )
      |> hd()

    wire = StunFixtures.binding_success_wire()

    send_recv = fn _req, _endpoint -> {:ok, wire} end

    assert {:ok, srflx} =
             Gather.query_srflx({{0, 0, 0, 0}, 50_000}, host, "stun:127.0.0.1:3478",
               send_recv: send_recv
             )

    assert srflx.type == "srflx"
  end

  test "gather_with_timeout returns host-only when send_recv is slow" do
    sock = {{192, 0, 2, 1}, 50_000}

    send_recv = fn _req, _endpoint ->
      Process.sleep(200)
      {:error, :timeout}
    end

    result =
      Gather.gather_with_timeout(sock,
        advertised_ip: {192, 0, 2, 1},
        include_loopback: false,
        stun_servers: ["stun:127.0.0.1:3478"],
        gather_timeout_ms: 50,
        send_recv: send_recv
      )

    assert length(result.host) == 1
    assert result.srflx == []
    assert result.relay == []
  end

  test "gather_with_timeout uses shared timeout budget for srflx and relay" do
    sock = {{192, 0, 2, 1}, 50_000}
    started = System.monotonic_time(:millisecond)

    send_recv = fn _req, _endpoint ->
      Process.sleep(150)
      {:error, :timeout}
    end

    result =
      Gather.gather_with_timeout(sock,
        advertised_ip: {192, 0, 2, 1},
        include_loopback: false,
        stun_servers: ["stun:127.0.0.1:3478"],
        turn_servers: ["turn:127.0.0.1:3478"],
        gather_timeout_ms: 50,
        send_recv: send_recv
      )

    elapsed = System.monotonic_time(:millisecond) - started

    assert length(result.host) == 1
    assert result.srflx == []
    assert result.relay == []
    assert elapsed < 120
  end

  test "parse_turn_server delegates to TURN client" do
    assert {:ok, {{127, 0, 0, 1}, 3478}} = Gather.parse_turn_server("turn:127.0.0.1")
  end

  test "build_relay priority is lowest among types" do
    host = ICE.candidate_priority(:host, 1, 65_535)
    relay = Gather.build_relay({{203, 0, 113, 1}, 50_000}).priority
    assert relay < host
    assert Gather.build_relay({{203, 0, 113, 1}, 50_000}).type == "relay"
  end

  test "query_relay with mock send_recv" do
    wire = TurnFixtures.allocate_success_wire()

    send_recv = fn _req, _endpoint -> {:ok, wire} end

    assert {:ok, %{candidate: cand, allocation: alloc}} =
             Gather.query_relay({{0, 0, 0, 0}, 0}, "turn:127.0.0.1:3478",
               send_recv: send_recv,
               turn_credentials: []
             )

    assert cand.type == "relay"
    assert alloc.relay == {{203, 0, 113, 99}, 49_999}
  end

  test "gather_with_timeout includes relay from mock" do
    wire = TurnFixtures.allocate_success_wire()
    send_recv = fn _req, _endpoint -> {:ok, wire} end

    result =
      Gather.gather_with_timeout({{192, 0, 2, 1}, 50_000},
        advertised_ip: {192, 0, 2, 1},
        include_loopback: false,
        turn_servers: ["turn:127.0.0.1:3478"],
        send_recv: send_recv
      )

    assert length(result.relay) == 1
    assert hd(result.relay).type == "relay"
  end
end
