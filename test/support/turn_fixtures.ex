defmodule XGW.Test.TurnFixtures do
  @moduledoc false

  alias XMediaLib.Stun

  @doc false
  def allocate_challenge(nonce \\ "nonce", realm \\ "xgw.test", transactionid \\ nil) do
    %Stun{
      class: :error,
      method: :allocate,
      transactionid: transactionid || :rand.uniform(0xFFFFFFFFFFFF),
      fingerprint: true,
      attrs: %{
        error_code: {401, "Unauthorized"},
        nonce: nonce,
        realm: realm
      }
    }
  end

  @doc false
  def allocate_success(attrs \\ []) do
    attrs = Map.new(attrs)

    {relay_ip, relay_port} =
      Map.get(attrs, :xor_relayed_address, {{203, 0, 113, 99}, 49_999})

    %Stun{
      class: :success,
      method: :allocate,
      transactionid: Map.get(attrs, :transactionid, :rand.uniform(0xFFFFFFFFFFFF)),
      fingerprint: true,
      attrs: %{
        xor_relayed_address: {relay_ip, relay_port},
        lifetime: Map.get(attrs, :lifetime, <<600::32>>)
      }
    }
  end

  @doc false
  def allocate_success_wire(attrs \\ []) do
    attrs |> Map.new() |> allocate_success() |> Stun.encode()
  end

  @doc false
  def allocate_challenge_wire(opts \\ []) do
    opts = Map.new(opts)
    nonce = Map.get(opts, :nonce, "nonce")
    realm = Map.get(opts, :realm, "xgw.test")
    tid = Map.get(opts, :transactionid)
    allocate_challenge(nonce, realm, tid) |> Stun.encode()
  end

  @doc false
  def refresh_success(lifetime_s \\ 600, transactionid \\ nil) do
    %Stun{
      class: :success,
      method: :refresh,
      transactionid: transactionid || :rand.uniform(0xFFFFFFFFFFFF),
      fingerprint: true,
      attrs: %{lifetime: <<lifetime_s::32>>}
    }
  end

  @doc false
  def create_permission_success(transactionid \\ nil) do
    %Stun{
      class: :success,
      method: :createperm,
      transactionid: transactionid || :rand.uniform(0xFFFFFFFFFFFF),
      fingerprint: true,
      attrs: %{}
    }
  end

  @doc false
  def channel_bind_success(transactionid \\ nil) do
    %Stun{
      class: :success,
      method: :channelbind,
      transactionid: transactionid || :rand.uniform(0xFFFFFFFFFFFF),
      fingerprint: true,
      attrs: %{}
    }
  end

  @doc false
  def start_echo_server(opts \\ []) do
    mapped = Keyword.get(opts, :mapped, {{203, 0, 113, 99}, 49_999})
    auth? = Keyword.get(opts, :auth?, false)
    realm = Keyword.get(opts, :realm, "xgw.test")
    nonce = Keyword.get(opts, :nonce, "nonce")
    username = Keyword.get(opts, :username, "user")
    password = Keyword.get(opts, :password, "pass")
    counter = Keyword.get(opts, :counter)

    {:ok, sock} = :gen_udp.open(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(sock)

    pid =
      spawn_link(fn ->
        echo_loop(sock, %{
          auth?: auth?,
          realm: realm,
          nonce: nonce,
          username: username,
          password: password,
          mapped: mapped,
          counter: counter
        })
      end)

    {port, pid, sock}
  end

  defp echo_loop(sock, cfg) do
    case recv_datagram(sock) do
      {:ok, reply_ip, reply_port, data} ->
        _ = respond(data, sock, reply_ip, reply_port, cfg)
        echo_loop(sock, cfg)

      _ ->
        echo_loop(sock, cfg)
    end
  end

  defp respond(data, sock, reply_ip, reply_port, cfg) do
    # ChannelData is not STUN; must not call Stun.decode on it (can raise).
    case data do
      <<chan::16, _len::16, _::binary>> when chan in 0x4000..0x7FFF ->
        if ref = cfg.counter do
          Agent.update(ref, fn
            n when is_integer(n) -> n + 1
            {n, _last} -> {n + 1, data}
          end)
        end

        :ok

      _ ->
        case Stun.decode(data) do
          {:ok, req} ->
            cond do
              req.method == :allocate and req.class == :request and cfg.auth? and
                  not authed?(req, cfg) ->
                Stun.encode(allocate_challenge(cfg.nonce, cfg.realm, req.transactionid))
                |> send_reply(sock, reply_ip, reply_port)

              req.method == :allocate and req.class == :request ->
                Stun.encode(
                  allocate_success(xor_relayed_address: cfg.mapped, transactionid: req.transactionid)
                )
                |> send_reply(sock, reply_ip, reply_port)

              req.method == :refresh and req.class == :request ->
                Stun.encode(refresh_success(600, req.transactionid))
                |> send_reply(sock, reply_ip, reply_port)

              req.method == :createperm and req.class == :request ->
                Stun.encode(create_permission_success(req.transactionid))
                |> send_reply(sock, reply_ip, reply_port)

              req.method == :channelbind and req.class == :request ->
                Stun.encode(channel_bind_success(req.transactionid))
                |> send_reply(sock, reply_ip, reply_port)

              req.method == :send and req.class == :indication ->
                if ref = cfg.counter do
                  Agent.update(ref, fn
                    n when is_integer(n) -> n + 1
                    {n, last} -> {n + 1, last}
                  end)
                end

                forward_send_indication(req, sock, cfg)

              true ->
                :ok
            end

          _ ->
            :ok
        end
    end
  end

  defp forward_send_indication(%Stun{attrs: attrs}, sock, _cfg) do
    with {peer_ip, peer_port} <- Map.get(attrs, :xor_peer_address),
         data when is_binary(data) and data != <<>> <- Map.get(attrs, :data) do
      :gen_udp.send(sock, peer_ip, peer_port, data)
    else
      _ -> :ok
    end
  end

  defp authed?(req, cfg) do
    attrs = req.attrs || %{}
    attrs[:username] == cfg.username and Map.has_key?(attrs, :message_integrity)
  end

  defp send_reply(wire, sock, ip, port) do
    :gen_udp.send(sock, ip, port, wire)
  end

  defp recv_datagram(sock) do
    case :gen_udp.recv(sock, 2048, 5_000) do
      {:ok, {ip, port, data}} -> {:ok, ip, port, data}
      {:ok, data} -> {:ok, {127, 0, 0, 1}, 0, data}
      other -> other
    end
  end
end
