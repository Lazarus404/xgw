defmodule XGW.ICE.LiteTest do
  use ExUnit.Case, async: true

  alias XGW.ICE.Lite
  alias XMediaLib.SDP.Candidate
  alias XMediaLib.Stun

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

  test "merge_remote_candidates dedups and sorts by priority descending" do
    low = cand(100, "192.0.2.1", 5000)
    high = cand(200, "192.0.2.2", 5001)
    dup = cand(200, "192.0.2.2", 5001)

    merged = Lite.merge_remote_candidates([low, dup], [high])
    assert Enum.map(merged, & &1.priority) == [200, 100]
    assert length(merged) == 2
  end

  test "add_remote_candidate records end-of-candidates without candidate line" do
    ice = Lite.new(ice_ufrag: "a", ice_pwd: "b", remote_ice_ufrag: "c")

    assert {:ok, ice2} = Lite.add_remote_candidate(ice, %{end_of_candidates: true})
    assert ice2.remote_candidates_eoc?
    assert ice2.remote_candidates == []
  end

  test "add_remote_candidate merges trickle line" do
    ice = Lite.new(ice_ufrag: "svr", ice_pwd: "pwd", remote_ice_ufrag: "cli", bundle_mids: ["0"])

    assert {:ok, ice2} =
             Lite.add_remote_candidate(ice, %{
               candidate: "candidate:2 1 UDP 2122260223 192.0.2.10 50000 typ srflx",
               mid: "0"
             })

    assert length(ice2.remote_candidates) == 1
    assert hd(ice2.remote_candidates).type == "srflx"
  end

  test "add_remote_candidate rejects unknown mid when bundle mids set" do
    ice = Lite.new(bundle_mids: ["0"])

    assert {:error, :media_not_found} =
             Lite.add_remote_candidate(ice, %{
               candidate: "candidate:1 1 UDP 2122260223 192.0.2.10 50000 typ host",
               mid: "9"
             })
  end

  test "handle_binding connectivity check sets connected" do
    ice =
      Lite.new(
        ice_ufrag: "svr",
        ice_pwd: "serverpasswordpassword",
        remote_ice_ufrag: "cli"
      )

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
          ice_controlling: <<1, 2, 3, 4, 5, 6, 7, 8>>
        }
      }
      |> Stun.encode()

    from = {{127, 0, 0, 1}, 9000}

    assert {:connected, reply, ice2} = Lite.handle_binding(req, from, ice)
    assert is_binary(reply)
    assert ice2.connected?
    assert ice2.selected == from
  end

  test "handle_binding keeps selected on later checks unless USE-CANDIDATE" do
    ice =
      Lite.new(
        ice_ufrag: "svr",
        ice_pwd: "serverpasswordpassword",
        remote_ice_ufrag: "cli"
      )

    first = {{127, 0, 0, 1}, 9000}
    second = {{192, 168, 0, 5}, 9001}

    req = fn tid, attrs ->
      %Stun{
        class: :request,
        method: :binding,
        transactionid: tid,
        integrity: true,
        key: "serverpasswordpassword",
        fingerprint: true,
        attrs: Map.merge(%{username: "svr:cli", ice_controlling: <<1, 2, 3, 4, 5, 6, 7, 8>>}, attrs)
      }
      |> Stun.encode()
    end

    assert {:connected, _, ice2} = Lite.handle_binding(req.(1, %{}), first, ice)
    assert ice2.selected == first

    assert {:reply, _, ice3} = Lite.handle_binding(req.(2, %{}), second, ice2)
    assert ice3.selected == first

    assert {:reply, _, ice4} =
             Lite.handle_binding(req.(3, %{use_candidate: <<>>}), second, ice3)

    assert ice4.selected == second
  end

  test "add_remote_candidate accepts prflx type" do
    ice = Lite.new([])

    assert {:ok, ice2} =
             Lite.add_remote_candidate(ice, %{
               candidate: "candidate:1 1 UDP 1 192.0.2.1 5000 typ prflx"
             })

    assert hd(ice2.remote_candidates).type == "prflx"
  end

  test "handle_binding returns consent on binding success response" do
    ice =
      Lite.new(
        ice_ufrag: "svr",
        ice_pwd: "localpwd",
        remote_ice_ufrag: "cli",
        remote_ice_pwd: "remotepwd"
      )

    from = {{127, 0, 0, 1}, 5000}

    success =
      %Stun{
        class: :success,
        method: :binding,
        transactionid: 999,
        integrity: true,
        key: "remotepwd",
        fingerprint: true,
        attrs: %{xor_mapped_address: from}
      }
      |> Stun.encode()

    assert {:consent, ^ice} = Lite.handle_binding(success, from, ice)
  end

  test "endpoint/1 parses candidate ip and port" do
    assert Lite.endpoint(cand(1, "192.0.2.10", 50000)) == {{192, 0, 2, 10}, 50000}
  end
end
