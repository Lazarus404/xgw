defmodule XGW.DTLSTest do
  use XGW.Test.Case

  alias XGW.{DTLS, Listener}

  @moduletag :external

  test "loopback handshake and SRTP key export" do
    assert {:ok, listener} = Listener.start_link(port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    listen_sock = Listener.listen_sock(listener)
    port = Listener.port(listener)
    client_dir = Path.join(System.tmp_dir!(), "xgw-dtls-test-client")
    {client_cert, client_key} = XGW.Certs.ensure!(client_dir)

    parent = self()

    client_task =
      Task.async(fn ->
        {:ok, client_sock} =
          :ssl.connect(~c"127.0.0.1", port,
            verify: :verify_none,
            certfile: String.to_charlist(client_cert),
            keyfile: String.to_charlist(client_key),
            protocol: :dtls,
            versions: [:"dtlsv1.2"],
            use_srtp: %{protection_profiles: [<<0, 1>>]}
          )

        send(parent, {:client_ready, client_sock})

        receive do
          :close -> :ssl.close(client_sock)
        end
      end)

    assert {:ok, server_sock} = DTLS.handshake(listen_sock)
    assert_receive {:client_ready, client_sock}, 5_000
    assert is_tuple(client_sock)

    assert {:ok, {ck, cs, sk, ss}} = DTLS.export_srtp_keys(server_sock)
    assert byte_size(ck) == 16
    assert byte_size(cs) == 14
    assert byte_size(sk) == 16
    assert byte_size(ss) == 14

    send(client_task.pid, :close)
    Task.await(client_task, 5_000)
    :ssl.close(server_sock)
  end

  test "post-handshake application data is delivered as binary in active mode" do
    assert {:ok, listener} = Listener.start_link(port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    listen_sock = Listener.listen_sock(listener)
    port = Listener.port(listener)
    client_dir = Path.join(System.tmp_dir!(), "xgw-dtls-appdata-active")
    {client_cert, client_key} = XGW.Certs.ensure!(client_dir)

    {:ok, _accept_pid} = DTLS.start_accept(listen_sock, self())

    parent = self()

    client_task =
      Task.async(fn ->
        {:ok, client_sock} =
          :ssl.connect(~c"127.0.0.1", port,
            verify: :verify_none,
            certfile: String.to_charlist(client_cert),
            keyfile: String.to_charlist(client_key),
            protocol: :dtls,
            versions: [:"dtlsv1.2"],
            use_srtp: %{protection_profiles: [<<0, 1>>]},
            mode: :binary,
            active: false
          )

        send(parent, {:client_ready, client_sock})

        receive do
          {:send, data} ->
            :ok = :ssl.send(client_sock, data)
            send(parent, :sent)
        end

        receive do
          :close -> :ssl.close(client_sock)
        end
      end)

    assert_receive {:client_ready, _client_sock}, 5_000
    assert_receive {:xgw_internal, :dtls_ready, ssl_sock, {:ok, _keys}}, 5_000

    assert :ok = :ssl.setopts(ssl_sock, active: :once)
    send(client_task.pid, {:send, "sctp-init"})
    assert_receive :sent, 2_000

    assert_receive {:ssl, ^ssl_sock, data}, 5_000
    assert is_binary(data)
    assert data == "sctp-init"

    send(client_task.pid, :close)
    Task.await(client_task, 5_000)
    :ssl.close(ssl_sock)
  end

  test "start_accept keeps the DTLS socket open after the handshake task returns" do
    assert {:ok, listener} = Listener.start_link(port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    listen_sock = Listener.listen_sock(listener)
    port = Listener.port(listener)
    client_dir = Path.join(System.tmp_dir!(), "xgw-dtls-test-keep-open")
    {client_cert, client_key} = XGW.Certs.ensure!(client_dir)

    {:ok, accept_pid} = DTLS.start_accept(listen_sock, self())

    parent = self()

    client_task =
      Task.async(fn ->
        {:ok, client_sock} =
          :ssl.connect(~c"127.0.0.1", port,
            verify: :verify_none,
            certfile: String.to_charlist(client_cert),
            keyfile: String.to_charlist(client_key),
            protocol: :dtls,
            versions: [:"dtlsv1.2"],
            use_srtp: %{protection_profiles: [<<0, 1>>]}
          )

        send(parent, {:client_ready, client_sock})

        receive do
          :close -> :ssl.close(client_sock)
        end
      end)

    assert_receive {:client_ready, _client_sock}, 5_000
    assert_receive {:xgw_internal, :dtls_ready, ssl_sock, {:ok, _keys}}, 5_000

    wait_until_dead(accept_pid, 1_000)
    refute Process.alive?(accept_pid)
    assert {:ok, _} = :ssl.connection_information(ssl_sock)

    send(client_task.pid, :close)
    Task.await(client_task, 5_000)
    :ssl.close(ssl_sock)
  end

  defp wait_until_dead(pid, timeout_ms) do
    ref = Process.monitor(pid)

    receive do
      {:DOWN, ^ref, :process, ^pid, _} -> :ok
    after
      timeout_ms -> :ok
    end
  end
end
