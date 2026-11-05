defmodule XGW.Peer.TurnTest do
  use ExUnit.Case, async: true

  alias XGW.Peer.Turn
  alias XMediaLib.Stun

  test "allocations_cover_relay_locals? requires matching relay endpoints" do
    locals = [
      %{type: "relay", ip: "1.2.3.4", port: 3478},
      %{type: "host", ip: "127.0.0.1", port: 9}
    ]

    allocs = [%{relay: {{1, 2, 3, 4}, 3478}}]
    assert Turn.allocations_cover_relay_locals?(allocs, locals)

    refute Turn.allocations_cover_relay_locals?([], locals)
    refute Turn.allocations_cover_relay_locals?(allocs, [%{type: "host", ip: "127.0.0.1", port: 9}])
  end

  test "unwrap_data_indication extracts peer and inner STUN" do
    inner = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19>>

    wire =
      Stun.encode(%Stun{
        class: :indication,
        method: 7,
        fingerprint: false,
        transactionid: 1,
        attrs: %{
          xor_peer_address: {{127, 0, 0, 1}, 5000},
          data: inner
        }
      })

    assert {:ok, ^inner, {{127, 0, 0, 1}, 5000}} = Turn.unwrap_data_indication(wire)
    assert :not_turn_data = Turn.unwrap_data_indication(<<"RTP", 0, 1, 2, 3>>)
  end
end
