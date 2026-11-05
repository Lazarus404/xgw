defmodule XGW.Trunk.Pipe do
  @moduledoc """
  Bidirectional UDP + SRTP trunk between media edges.

  ## What problem this solves

  Multi-home rooms need an SFU-to-SFU media path that is not WebRTC/ICE and not
  Distributed Erlang. This GenServer owns one UDP socket, encrypts RTP/RTCP with
  a pre-shared key, multiplexes opaque datachannel frames, and delivers inbound
  plaintext to a `handler` pid.

  ## RFCs

  * RFC 3711 -- SRTP on RTP/RTCP frames
  * RFC 3550 -- RTP payloads after unprotect
  """

  use GenServer

  alias XGW.Trunk.{Crypto, Frame}
  alias XMediaLib.Rtp

  @type stats :: %{udp_in: non_neg_integer(), udp_out: non_neg_integer()}

  defstruct handler: nil,
            socket: nil,
            peer_ip: nil,
            peer_port: nil,
            srtp: nil,
            udp_in: 0,
            udp_out: 0,
            labels: %{},
            refs: %{}

  @doc """
  Starts a trunk pipe.

  Opts:

  * `:handler` - pid that receives inbound `{__MODULE__, kind, pipe, ...}` messages
  * `:master_key` / `:master_salt` - shared lab keys (both directions)
  * `:local_write_key` / `:local_write_salt` / `:remote_write_key` /
    `:remote_write_salt` - directional write keys (preferred)
  * `:port` - optional bind port (default `0` ephemeral)
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Returns the local `{ip, port}` of the UDP socket.
  """
  @spec local_addr(pid()) :: {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def local_addr(pipe) when is_pid(pipe), do: GenServer.call(pipe, :local_addr)

  @doc """
  Sets the remote edge UDP address for outbound frames.
  """
  @spec connect(pid(), :inet.ip_address(), :inet.port_number()) :: :ok
  def connect(pipe, ip, port) when is_pid(pipe) and is_integer(port) do
    GenServer.call(pipe, {:connect, ip, port})
  end

  @doc """
  Replaces the inbound handler pid (e.g. your edge-to-edge bridge process).
  """
  @spec set_handler(pid(), pid()) :: :ok
  def set_handler(pipe, handler) when is_pid(pipe) and is_pid(handler) do
    GenServer.call(pipe, {:set_handler, handler})
  end

  @doc """
  UDP in/out packet counters (lab assertion that media used UDP).
  """
  @spec stats(pid()) :: stats()
  def stats(pipe) when is_pid(pipe), do: GenServer.call(pipe, :stats)

  @doc """
  Encrypts and sends one RTP packet to the connected peer.
  """
  @spec send_rtp(pid(), non_neg_integer(), Rtp.t() | binary()) :: :ok | {:error, term()}
  def send_rtp(pipe, ssrc, packet) when is_pid(pipe) and is_integer(ssrc) do
    GenServer.call(pipe, {:send_rtp, ssrc, packet})
  end

  @doc """
  Sends an opaque datachannel payload labeled for demux on the far edge.
  """
  @spec send_dc(pid(), binary(), binary()) :: :ok | {:error, term()}
  def send_dc(pipe, label, data)
      when is_pid(pipe) and is_binary(label) and is_binary(data) do
    GenServer.call(pipe, {:send_dc, label, data})
  end

  @doc """
  Registers a label and returns a channel_ref for SendHandle / Forwarder.
  """
  @spec ensure_label(pid(), binary()) :: {:ok, reference()} | {:error, term()}
  def ensure_label(pipe, label) when is_pid(pipe) and is_binary(label) do
    GenServer.call(pipe, {:ensure_label, label})
  end

  @doc """
  Publishes RTP + datachannel SendHandle trunk passthrough for this pipe pid.
  """
  @spec publish_send_handles(pid()) :: :ok
  def publish_send_handles(pipe) when is_pid(pipe) do
    alias XGW.Peer.SendHandle

    SendHandle.publish_trunk_passthrough(
      pipe,
      {__MODULE__, :hot_send_rtp, pipe},
      {__MODULE__, :hot_send_dc, pipe}
    )
  end

  @doc """
  SendHandle RTP MFA sink (`apply(mod, fun, [pipe, ssrc, rtp])`).
  """
  @spec hot_send_rtp(pid(), non_neg_integer(), Rtp.t()) :: :ok | {:error, term()}
  def hot_send_rtp(pipe, ssrc, rtp) when is_pid(pipe) do
    send_rtp(pipe, ssrc, rtp)
  end

  @doc """
  SendHandle datachannel MFA sink (`apply(mod, fun, [pipe, ref, data, type])`).
  """
  @spec hot_send_dc(pid(), reference(), binary(), :string | :binary) :: :ok | {:error, term()}
  def hot_send_dc(pipe, channel_ref, data, _type \\ :string)
      when is_pid(pipe) and is_reference(channel_ref) and is_binary(data) do
    GenServer.call(pipe, {:send_dc_ref, channel_ref, data})
  end

  @impl true
  def init(opts) do
    handler = Keyword.fetch!(opts, :handler)
    port = Keyword.get(opts, :port, 0)
    srtp = srtp_from_opts(opts)

    case :gen_udp.open(port, [:binary, {:active, true}, {:ip, {127, 0, 0, 1}}, {:reuseaddr, true}]) do
      {:ok, socket} ->
        state = %__MODULE__{
          handler: handler,
          socket: socket,
          srtp: srtp
        }

        {:ok, state}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  defp srtp_from_opts(opts) do
    case Keyword.fetch(opts, :local_write_key) do
      {:ok, local_key} ->
        Crypto.new(
          local_key,
          Keyword.fetch!(opts, :local_write_salt),
          Keyword.fetch!(opts, :remote_write_key),
          Keyword.fetch!(opts, :remote_write_salt)
        )

      :error ->
        Crypto.new(Keyword.fetch!(opts, :master_key), Keyword.fetch!(opts, :master_salt))
    end
  end

  @impl true
  def handle_call(:local_addr, _from, %{socket: socket} = state) do
    case :inet.sockname(socket) do
      {:ok, {ip, port}} -> {:reply, {:ok, {ip, port}}, state}
      other -> {:reply, other, state}
    end
  end

  def handle_call({:connect, ip, port}, _from, state) do
    {:reply, :ok, %{state | peer_ip: ip, peer_port: port}}
  end

  def handle_call({:set_handler, handler}, _from, state) do
    {:reply, :ok, %{state | handler: handler}}
  end

  def handle_call(:stats, _from, state) do
    {:reply, %{udp_in: state.udp_in, udp_out: state.udp_out}, state}
  end

  def handle_call({:send_rtp, ssrc, packet}, _from, state) do
    case normalize_rtp(packet, ssrc) do
      {:ok, rtp} ->
        case Crypto.protect_rtp(state.srtp, rtp) do
          {:ok, wire, srtp} ->
            case udp_send(state, Frame.encode(:rtp, wire)) do
              :ok ->
                {:reply, :ok, %{state | srtp: srtp, udp_out: state.udp_out + 1}}

              {:error, reason} ->
                {:reply, {:error, reason}, %{state | srtp: srtp}}
            end

          {:error, srtp} ->
            {:reply, {:error, :encrypt_failed}, %{state | srtp: srtp}}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:send_dc, label, data}, _from, state) do
    body = Frame.encode_dc(label, data)

    case udp_send(state, Frame.encode(:dc, body)) do
      :ok ->
        {:reply, :ok, %{state | udp_out: state.udp_out + 1}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:ensure_label, label}, _from, state) do
    case Map.get(state.labels, label) do
      nil ->
        ref = make_ref()
        state = %{
          state
          | labels: Map.put(state.labels, label, ref),
            refs: Map.put(state.refs, ref, label)
        }

        {:reply, {:ok, ref}, state}

      ref ->
        {:reply, {:ok, ref}, state}
    end
  end

  def handle_call({:send_dc_ref, channel_ref, data}, _from, state) do
    case Map.fetch(state.refs, channel_ref) do
      {:ok, label} ->
        body = Frame.encode_dc(label, data)

        case udp_send(state, Frame.encode(:dc, body)) do
          :ok ->
            {:reply, :ok, %{state | udp_out: state.udp_out + 1}}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      :error ->
        {:reply, {:error, :unknown_label}, state}
    end
  end

  def handle_call({:send_rtcp, _packet}, _from, state) do
    # Lab: PLI/FIR toward a trunk pipe is a no-op (no RTCP multiplex yet).
    {:reply, :ok, state}
  end

  def handle_call(:close, _from, state) do
    {:stop, :normal, :ok, state}
  end

  @impl true
  def handle_cast({:send_rtp, ssrc, packet}, state) do
    case normalize_rtp(packet, ssrc) do
      {:ok, rtp} ->
        case Crypto.protect_rtp(state.srtp, rtp) do
          {:ok, wire, srtp} ->
            case udp_send(state, Frame.encode(:rtp, wire)) do
              :ok ->
                {:noreply, %{state | srtp: srtp, udp_out: state.udp_out + 1}}

              {:error, _} ->
                {:noreply, %{state | srtp: srtp}}
            end

          {:error, srtp} ->
            {:noreply, %{state | srtp: srtp}}
        end

      {:error, _} ->
        {:noreply, state}
    end
  end

  def handle_cast({:send_datachannel, channel_ref, data}, state) do
    handle_cast({:send_datachannel, channel_ref, data, :string}, state)
  end

  def handle_cast({:send_datachannel, channel_ref, data, _type}, state) do
    case Map.fetch(state.refs, channel_ref) do
      {:ok, label} ->
        body = Frame.encode_dc(label, data)

        case udp_send(state, Frame.encode(:dc, body)) do
          :ok ->
            {:noreply, %{state | udp_out: state.udp_out + 1}}

          {:error, _} ->
            {:noreply, state}
        end

      :error ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:udp, socket, _ip, _port, data}, %{socket: socket} = state) do
    state = %{state | udp_in: state.udp_in + 1}

    case Frame.decode(data) do
      {:ok, :rtp, ciphertext} ->
        case Crypto.unprotect_rtp(state.srtp, ciphertext) do
          {:ok, %Rtp{ssrc: ssrc} = rtp, srtp} ->
            send(state.handler, {__MODULE__, :rtp, self(), ssrc, rtp})
            {:noreply, %{state | srtp: srtp}}

          {:error, srtp} ->
            {:noreply, %{state | srtp: srtp}}
        end

      {:ok, :rtcp, ciphertext} ->
        case Crypto.unprotect_rtcp(state.srtp, ciphertext) do
          {:ok, rtcp, srtp} ->
            send(state.handler, {__MODULE__, :rtcp, self(), rtcp})
            {:noreply, %{state | srtp: srtp}}

          {:error, srtp} ->
            {:noreply, %{state | srtp: srtp}}
        end

      {:ok, :dc, body} ->
        case Frame.decode_dc(body) do
          {:ok, label, payload} ->
            send(state.handler, {__MODULE__, :dc, self(), label, payload})
            {:noreply, state}

          {:error, _} ->
            {:noreply, state}
        end

      {:error, _} ->
        {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{socket: socket}) when is_port(socket) do
    :gen_udp.close(socket)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  defp udp_send(%{peer_ip: nil}, _data), do: {:error, :not_connected}

  defp udp_send(%{socket: socket, peer_ip: ip, peer_port: port}, data) do
    :gen_udp.send(socket, ip, port, data)
  end

  defp normalize_rtp(%Rtp{} = rtp, ssrc), do: {:ok, %{rtp | ssrc: ssrc}}
  defp normalize_rtp(_other, _ssrc), do: {:error, :bad_rtp}
end
