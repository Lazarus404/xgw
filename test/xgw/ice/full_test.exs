defmodule XGW.ICE.FullTest do
  use ExUnit.Case, async: true

  alias XGW.ICE
  alias XGW.ICE.Full
  alias XMediaLib.SDP.Candidate
  alias XMediaLib.Stun

  defp config(setup \\ :passive) do
    %{
      bundle_mids: ["0"],
      remote_candidates: [
        %Candidate{
          foundation: "1",
          component_id: 1,
          transport: "udp",
          priority: 100,
          ip: "192.0.2.1",
          port: 5000,
          type: "host"
        }
      ],
      ice: %{
        local_ufrag: "svr",
        local_pwd: "serverpasswordpassword",
        remote_ufrag: "cli",
        remote_pwd: "clientpasswordpassword",
        local_setup: setup,
        remote_setup: :actpass
      }
    }
  end

  defp local_host do
    %Candidate{
      foundation: "9",
      component_id: 1,
      transport: "udp",
      priority: ICE.host_priority(1),
      ip: "127.0.0.1",
      port: 5000,
      type: "host"
    }
  end

  defp remote_at(ip, port) do
    %Candidate{
      foundation: "1",
      component_id: 1,
      transport: "udp",
      priority: 100,
      ip: ip,
      port: port,
      type: "host"
    }
  end

  defp full_ready(remote \\ nil) do
    remote = remote || hd(config().remote_candidates)

    assert {:ok, full} = Full.from_config(config())
    full = full |> Full.seed_remote_candidates([remote]) |> Full.seed_local_candidates([local_host()])
    Full.start_checking(full)
  end

  test "from_config selects controlled role for actpass + passive" do
    assert {:ok, full} = Full.from_config(config())

    full = Full.seed_remote_candidates(full, config().remote_candidates)

    assert full.phase == :gathering
    assert full.role == :controlled
    assert full.ice_ufrag == "svr"
    assert length(full.remote_candidates) == 1
  end

  test "from_config selects controlling role for actpass + active" do
    assert {:ok, full} = Full.from_config(config(:active))
    assert full.role == :controlling
  end

  test "from_config rejects unsupported setup combos" do
    config = put_in(config().ice[:remote_setup], :active)
    assert {:error, :unsupported_setup} = Full.from_config(config)
  end

  test "add_remote_candidate merges trickle and records EOC" do
    full = Full.new([])

    assert {:ok, full2} =
             Full.add_remote_candidate(full, %{
               candidate: "candidate:2 1 UDP 2122260223 192.0.2.10 50000 typ srflx",
               mid: "0"
             })

    assert length(full2.remote_candidates) == 1

    assert {:ok, full3} = Full.add_remote_candidate(full2, %{end_of_candidates: true})
    assert full3.remote_candidates_eoc?
  end

  test "checklist_inputs exposes remote candidates, empty local" do
    assert {:ok, full} = Full.from_config(config())
    full = Full.seed_remote_candidates(full, config().remote_candidates)
    inputs = Full.checklist_inputs(full)
    assert inputs.local == []
    assert length(inputs.remote) == 1
    assert hd(inputs.remote).foundation == "1"
  end

  test "seed_local_candidates merges host locals" do
    assert {:ok, full} = Full.from_config(config())
    local = local_host()
    full = Full.seed_local_candidates(full, [local])
    assert length(full.local_candidates) == 1
    assert Full.checklist_inputs(full).local == [local]
  end

  test "add_local_candidate merges srflx trickle" do
    assert {:ok, full} = Full.from_config(config())
    host = local_host()
    full = Full.seed_local_candidates(full, [host])

    srflx = %Candidate{
      foundation: "9",
      component_id: 1,
      transport: "udp",
      priority: ICE.candidate_priority(:srflx, 1, 65_535),
      ip: "203.0.113.50",
      port: 54_321,
      type: "srflx",
      rest: "raddr 127.0.0.1 rport 5000"
    }

    assert {:ok, full2} = Full.add_local_candidate(full, srflx)
    assert length(full2.local_candidates) == 2
    assert Enum.any?(full2.local_candidates, &(&1.type == "srflx"))
  end

  test "start_checking moves to checking phase" do
    full = full_ready()
    assert full.phase == :checking
    assert length(full.checklist) == 1
  end

  test "handle_stun accepts USE-CANDIDATE and moves to connected" do
    full = full_ready(remote_at("127.0.0.1", 54_321))

    req =
      %Stun{
        class: :request,
        method: :binding,
        transactionid: 1,
        integrity: true,
        key: "serverpasswordpassword",
        fingerprint: true,
        attrs: %{
          username: "svr:cli",
          priority: <<1::32>>,
          ice_controlling: <<1, 2, 3, 4, 5, 6, 7, 8>>,
          use_candidate: <<>>
        }
      }
      |> Stun.encode()

    from = {{127, 0, 0, 1}, 54_321}

    assert {:connected, reply, connected, ^from} = Full.handle_stun(req, from, full)
    assert connected.phase == :connected
    assert is_binary(reply)
    assert {:ok, %Stun{class: :success}} = Stun.decode(reply, "serverpasswordpassword")
  end

  test "handle_stun adds prflx remote and accepts USE-CANDIDATE from unknown address" do
    full = full_ready(remote_at("192.0.2.1", 5000))

    req =
      %Stun{
        class: :request,
        method: :binding,
        transactionid: 2,
        integrity: true,
        key: "serverpasswordpassword",
        fingerprint: true,
        attrs: %{
          username: "svr:cli",
          priority: <<50::32>>,
          ice_controlling: <<1, 2, 3, 4, 5, 6, 7, 8>>,
          use_candidate: <<>>
        }
      }
      |> Stun.encode()

    from = {{127, 0, 0, 1}, 54_321}

    assert {:connected, _reply, connected, ^from} = Full.handle_stun(req, from, full)
    assert connected.phase == :connected
    assert Enum.any?(connected.remote_candidates, &(&1.type == "prflx" and &1.port == 54_321))
    assert %{local: _, remote: _} = connected.nominated_pair
  end

  test "handle_stun TCP USE-CANDIDATE adds tcp prflx for ephemeral ICE-TCP peer" do
    local_tcp = %{local_host() | transport: "tcp", rest: "tcptype passive"}
    remote_tcp_active = %{remote_at("127.0.0.1", 9) | transport: "tcp", rest: "tcptype active"}

    assert {:ok, full} = Full.from_config(config())

    full =
      full
      |> Full.seed_remote_candidates([remote_tcp_active])
      |> Full.seed_local_candidates([local_tcp])
      |> Full.start_checking()

    req =
      %Stun{
        class: :request,
        method: :binding,
        transactionid: 3,
        integrity: true,
        key: "serverpasswordpassword",
        fingerprint: true,
        attrs: %{
          username: "svr:cli",
          priority: <<50::32>>,
          ice_controlling: <<1, 2, 3, 4, 5, 6, 7, 8>>,
          use_candidate: <<>>
        }
      }
      |> Stun.encode()

    # Real TCP peername is ephemeral, not port 9 from the active candidate line.
    from = {{127, 0, 0, 1}, 54_925}

    assert {:connected, _reply, connected, ^from} =
             Full.handle_stun(req, from, full, transport: :tcp)

    assert connected.phase == :connected

    assert Enum.any?(
             connected.remote_candidates,
             &(&1.type == "prflx" and &1.transport == "tcp" and &1.port == 54_925)
           )

    assert connected.nominated_pair.local.transport == "tcp"
    assert connected.nominated_pair.remote.transport == "tcp"
  end

  test "mark_completed moves connected to completed" do
    full = %{Full.new([]) | phase: :connected}
    assert Full.mark_completed(full).phase == :completed
    assert Full.mark_completed(%{full | phase: :checking}).phase == :checking
  end

  test "add_remote_candidate during checking preserves in_progress transaction" do
    full = full_ready()
    now = System.monotonic_time(:millisecond)
    assert {:send, _wire, _dest, full, _tid} = Full.tick(full, now)
    tid = hd(full.checklist).transaction_id
    assert hd(full.checklist).state == :in_progress

    assert {:ok, full2} =
             Full.add_remote_candidate(full, %{
               candidate: "candidate:3 1 UDP 2122260223 192.0.2.20 50001 typ host",
               mid: "0"
             })

    assert length(full2.checklist) == 2
    active = Enum.find(full2.checklist, &(&1.remote.ip == "192.0.2.1"))
    assert active.state == :in_progress
    assert active.transaction_id == tid
  end

  test "tick emits outbound check when checking" do
    full = full_ready()
    assert {:send, wire, dest, full2, _tid} = Full.tick(full, System.monotonic_time(:millisecond))
    assert is_binary(wire)
    assert dest == {{192, 0, 2, 1}, 5000}
    assert hd(full2.checklist).state == :in_progress
  end

  test "ice_restart resets to gathering" do
    full = full_ready() |> Full.ice_restart()
    assert full.phase == :gathering
    assert full.checklist == []
  end
end
