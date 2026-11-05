defmodule XGW.SpikeHTTPTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias XGW.{Spike.HTTP, Spike.Server, Test.SDPFixtures}
  alias Plug.Test

  setup do
    lock = XGW.Test.Helpers.lock_integration!()

    on_exit(fn ->
      stop_spike_server()
      XGW.Test.Helpers.unlock_integration!(lock)
    end)

    stop_spike_server()

    {:ok, _pid} = Server.start_link(port: 0)
    :ok
  end

  defp stop_spike_server do
    case Process.whereis(Server) do
      pid when is_pid(pid) ->
        if Process.alive?(pid) do
          _ =
            try do
              GenServer.stop(pid, :normal, 5_000)
            catch
              :exit, _ -> :ok
            end
        end

      _ ->
        :ok
    end
  end

  test "GET /candidates returns lines since index" do
    :sys.replace_state(Server, fn s ->
      %{s | trickle_lines: ["candidate:99 1 UDP 1 127.0.0.1 9 typ host"]}
    end)

    conn = Test.conn(:get, "/candidates?since=0")
    conn = HTTP.call(conn, [])

    assert conn.status == 200

    assert %{"candidates" => ["candidate:99 1 UDP 1 127.0.0.1 9 typ host"], "next" => 1} =
             JSON.decode!(conn.resp_body)
  end

  test "GET / serves spike page with transport debug hooks" do
    conn = Test.conn(:get, "/")
    conn = HTTP.call(conn, [])

    assert conn.status == 200
    assert conn.resp_body =~ "async function debugSnapshot()"
    assert conn.resp_body =~ "function selectedCandidatePair(stats)"
    assert conn.resp_body =~ "outboundRtp"
    assert conn.resp_body =~ "transport="
  end

  test "POST /candidate forwards trickle remote to peer" do
    offer = SDPFixtures.minimal_offer("cli1", "clientpasswordpassword")

    assert is_binary(Server.answer(offer))

    body =
      JSON.encode!(%{
        "candidate" => "candidate:2 1 UDP 1853824767 127.0.0.1 54321 typ host",
        "mid" => "0"
      })

    conn =
      :post
      |> Test.conn("/candidate", body)
      |> Map.put(:req_headers, [{"content-type", "application/json"}])

    conn = HTTP.call(conn, [])
    assert conn.status == 204
    assert :sys.get_state(Server).remote_trickle_count == 1

    peer = :sys.get_state(Server).peer
    if Process.alive?(peer), do: XGW.Peer.close(peer)
  end

  test "POST /offer honors X-Spike-Codec header for PCMU answer" do
    offer = """
    v=0
    o=- 1 2 IN IP4 127.0.0.1
    s=-
    t=0 0
    a=group:BUNDLE 0
    m=audio 9 UDP/TLS/RTP/SAVPF 111 0
    c=IN IP4 0.0.0.0
    a=ice-ufrag:cli1
    a=ice-pwd:clientpasswordpassword
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=setup:actpass
    a=mid:0
    a=sendrecv
    a=rtcp-mux
    a=rtpmap:111 opus/48000/2
    a=rtpmap:0 PCMU/8000
    """

    conn =
      :post
      |> Test.conn("/offer", offer)
      |> Map.put(:req_headers, [
        {"content-type", "application/sdp"},
        {"x-spike-codec", "pcmu"}
      ])

    conn = HTTP.call(conn, [])
    assert conn.status == 200
    assert conn.resp_body =~ "PCMU/8000"
    refute conn.resp_body =~ "opus"

    peer = :sys.get_state(Server).peer
    if Process.alive?(peer), do: XGW.Peer.close(peer)
  end
end
