defmodule XGW.ICETest do
  use ExUnit.Case, async: true
  doctest XGW.ICE

  alias XGW.ICE
  alias XMediaLib.SDP.Candidate

  defp cand(priority, ip, port, type \\ "host") do
    %Candidate{
      foundation: "1",
      component_id: 1,
      transport: "udp",
      priority: priority,
      ip: ip,
      port: port,
      type: type
    }
  end

  test "host_priority matches RFC 8445 host formula" do
    assert ICE.host_priority(1) == 126 * Bitwise.bsl(1, 24) + 65_535 * Bitwise.bsl(1, 8) + 255
  end

  test "type_preference and candidate_priority golden values" do
    assert ICE.type_preference(:host) == 126
    assert ICE.type_preference(:srflx) == 100
    assert ICE.type_preference(:prflx) == 110
    assert ICE.type_preference(:relay) == 0

    host_p = ICE.candidate_priority(:host, 1, 65_535)
    srflx_p = ICE.candidate_priority(:srflx, 1, 65_535)
    assert srflx_p < host_p
    assert host_p == ICE.host_priority(1)
  end

  test "local_preference_from_priority inverts host priority" do
    host = cand(ICE.host_priority(1, 42_000), "192.0.2.1", 5000)
    assert ICE.local_preference_from_priority(host) == 42_000
  end

  test "role actpass + passive -> controlled" do
    assert {:ok, :controlled} = ICE.role(:actpass, :passive)
  end

  test "role actpass + active -> controlling" do
    assert {:ok, :controlling} = ICE.role(:actpass, :active)
  end

  test "role rejects unsupported setup combos" do
    assert {:error, :unsupported_setup} = ICE.role(:active, :passive)
  end

  test "merge_remote dedups and sorts by priority descending" do
    low = cand(100, "192.0.2.1", 5000)
    high = cand(200, "192.0.2.2", 5001)
    dup = cand(200, "192.0.2.2", 5001)

    merged = ICE.merge_remote([low, dup], [high])
    assert Enum.map(merged, & &1.priority) == [200, 100]
    assert length(merged) == 2
  end

  test "valid? requires foundation and allowed type" do
    assert ICE.valid?(cand(1, "192.0.2.1", 5000))
    refute ICE.valid?(%Candidate{type: "host", foundation: nil, ip: "1", port: 1})
    assert ICE.valid?(%Candidate{type: "prflx", foundation: "1", ip: "1", port: 1})
    refute ICE.valid?(%Candidate{type: "unknown", foundation: "1", ip: "1", port: 1})
  end

  test "type_atom and transport_atom map SDP strings" do
    assert ICE.type_atom("host") == :host
    assert ICE.transport_atom("UDP") == :udp
  end

  test "foundation is deterministic string" do
    f = ICE.foundation("host", {192, 0, 2, 1}, "udp")
    assert is_binary(f)
    assert f == ICE.foundation("host", "192.0.2.1", "udp")
  end

  test "candidate_line formats SDP attribute value" do
    c = %XMediaLib.SDP.Candidate{
      foundation: "1",
      component_id: 1,
      transport: "udp",
      priority: 100,
      ip: "192.0.2.1",
      port: 5000,
      type: "host"
    }

    assert ICE.candidate_line(c) ==
             "candidate:1 1 UDP 100 192.0.2.1 5000 typ host"
  end

  test "candidate_line includes srflx raddr and rport" do
    c = %Candidate{
      foundation: "9",
      component_id: 1,
      transport: "udp",
      priority: 100,
      ip: "203.0.113.50",
      port: 54_321,
      type: "srflx",
      rest: "raddr 127.0.0.1 rport 5000"
    }

    assert ICE.candidate_line(c) ==
             "candidate:9 1 UDP 100 203.0.113.50 54321 typ srflx raddr 127.0.0.1 rport 5000"
  end
end
