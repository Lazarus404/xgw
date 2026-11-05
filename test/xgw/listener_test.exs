defmodule XGW.ListenerTest do
  use XGW.Test.Case

  alias XGW.{Listener, Peer}
  alias XGW.Test.SDPFixtures
  alias XMediaLib.Stun

  test "routes STUN to peer and DTLS inject does not deliver raw packets" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    port = Listener.port(listener)

    parent = self()
    server_pwd = "serverpasswordpassword"
    client_ufrag = "cli1"

    assert {:ok, peer} =
             Peer.start_supervised(handler: parent, listener: listener, ice_lite: true)

    assert :ok =
             SDPFixtures.apply_with_listener(
               peer,
               listener,
               client_ufrag,
               "clientpasswordpassword",
               "svr1",
               server_pwd
             )

    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    {:ok, client_port} = :inet.port(sock)

    req = stun_binding(server_pwd, "svr1:#{client_ufrag}", true)
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, req)
    assert_receive {:xgw, :ice_connected, ^peer}, 2000
    assert :dtls_wait = Peer.phase(peer)
    stop_dtls_accept_task(peer)

    dtls = <<22, 0, 1>>
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, dtls)
    refute_receive {:xgw, :packet, _, _, _, _}, 200

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt}, {{127, 0, 0, 1}, client_port})
    assert_receive {:xgw, :dtls_connected, ^peer}

    alias XMediaLib.{Rtp, Srtp}

    rtp_plain = %Rtp{
      padding: 0,
      marker: 0,
      payload_type: 111,
      sequence_number: 1,
      timestamp: 2,
      ssrc: 1001,
      csrcs: [],
      extension: nil,
      payload: <<>>
    }

    ctx = Srtp.new_ctx(1001, :aes_cm, :hmac_sha1, key, salt, 10)
    {:ok, rtp, _} = Srtp.encrypt(rtp_plain, ctx)
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, rtp)
    assert_receive {:xgw, :rtp, ^peer, %Rtp{}, meta}, 2000
    assert elem(meta.from, 1) == client_port
    assert meta.mid == "0"
    assert is_integer(meta.arrival_us)

    :gen_udp.close(sock)
    assert :ok = Peer.close(peer)
    assert_peer_closed(peer, :normal)
  end

  test "turn_request delivers interleaved Data Indications to peer" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    parent = self()
    {:ok, forwarder} = GenServer.start_link(__MODULE__.PacketForwarder, parent)
    on_exit(fn -> if Process.alive?(forwarder), do: GenServer.stop(forwarder) end)
    assert :ok = Listener.register_peer(listener, forwarder)

    {:ok, turn_sock} = :gen_udp.open(0, [:binary, active: false])
    on_exit(fn -> :gen_udp.close(turn_sock) end)
    {:ok, turn_port} = :inet.port(turn_sock)

    # TURN replies with an unrelated Data Indication first, then the matching response.
    turn_task =
      Task.async(fn ->
        receive do
          :go -> :ok
        after
          2_000 -> :timeout
        end

        case :gen_udp.recv(turn_sock, 0, 2_000) do
          {:ok, {lip, lport, req}} ->
            <<_type::16, _len::16, _magic::32, tid::binary-size(12), _::binary>> = req

            data_ind =
              Stun.encode(%Stun{
                class: :indication,
                method: 7,
                fingerprint: false,
                transactionid: 99,
                attrs: %{
                  xor_peer_address: {{203, 0, 113, 1}, 40_000},
                  data: <<"inner-binding">>
                }
              })

            resp =
              Stun.encode(%Stun{
                class: :success,
                method: :createperm,
                fingerprint: false,
                transactionid: :binary.decode_unsigned(tid),
                attrs: %{}
              })

            :ok = :gen_udp.send(turn_sock, lip, lport, data_ind)
            :ok = :gen_udp.send(turn_sock, lip, lport, resp)

          other ->
            other
        end
      end)

    :ok = :gen_udp.controlling_process(turn_sock, turn_task.pid)
    send(turn_task.pid, :go)

    req =
      Stun.encode(%Stun{
        class: :request,
        method: :createperm,
        fingerprint: false,
        transactionid: 42,
        attrs: %{xor_peer_address: {{203, 0, 113, 1}, 40_000}}
      })

    assert {:ok, resp} =
             Listener.turn_request(listener, {127, 0, 0, 1}, turn_port, 2_000, req)

    assert {:ok, %Stun{class: :success, method: :createperm}} = Stun.decode(resp)
    # Data Indication is unwrapped and re-demuxed with xor-peer as from.
    assert_receive {:packet, :unknown, <<"inner-binding">>, %{from: {{203, 0, 113, 1}, 40_000}}},
                   500
    assert :ok = Task.await(turn_task)
  end

  defmodule PacketForwarder do
    @moduledoc false
    use GenServer

    def init(parent), do: {:ok, parent}

    def handle_cast({:packet, kind, data, meta}, parent) do
      send(parent, {:packet, kind, data, meta})
      {:noreply, parent}
    end
  end

  defp stop_dtls_accept_task(peer) do
    case :sys.get_state(peer).dtls_task do
      %Task{pid: pid} when is_pid(pid) ->
        Process.unlink(pid)
        Process.exit(pid, :kill)
        :sys.replace_state(peer, fn s -> %{s | dtls_task: nil} end)

      pid when is_pid(pid) ->
        Process.unlink(pid)
        Process.exit(pid, :kill)
        :sys.replace_state(peer, fn s -> %{s | dtls_task: nil} end)

      _ ->
        :ok
    end
  end

  defp stun_binding(pwd, username, connectivity?) do
    attrs =
      if connectivity? do
        %{username: username, priority: <<0, 0, 0, 1>>, ice_controlling: <<1, 2, 3, 4, 5, 6, 7, 8>>}
      else
        %{username: username}
      end

    %Stun{
      class: :request,
      method: :binding,
      transactionid: 1_234_567_890,
      integrity: true,
      key: pwd,
      fingerprint: true,
      attrs: attrs
    }
    |> Stun.encode()
  end
end
