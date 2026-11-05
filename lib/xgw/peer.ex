defmodule XGW.Peer do
  @moduledoc """
  One remote WebRTC client: runs ICE, DTLS, and SRTP, then gives your app
  plaintext media and data-channel events.

  ## Mental model

  Think of a Peer as the server-side half of a browser `RTCPeerConnection`.
  Your application (SFU, MCU, or signaling server) still owns signaling: it
  negotiates SDP offer/answer, then calls `apply_descriptions/4` here. After
  that, XGW owns the wire protocols until the Peer closes.

  Lifecycle in short:

  ```text
  apply SDP -> ICE connects -> DTLS connects -> SRTP keys ready -> media I/O
  ```

  ## Outbound media (after `{:xgw, :dtls_connected, peer_ref}`)

    * `{:ok, handle} = XGW.Peer.outbound_handle(peer_ref)` then
      `XGW.Peer.SendHandle.send_rtp(handle, ssrc, packet)` (hot path; no GenServer)
    * `:ok = XGW.Peer.send_rtp(peer_ref, ssrc, %XMediaLib.Rtp{} | binary())`
    * `:ok = XGW.Peer.send_rtp_async(peer_ref, ssrc, packet)` (cast; still shares ETS encrypt)
    * `:ok = XGW.Peer.send_rtcp(peer_ref, %XMediaLib.Rtcp{} | binary())`

  The `ssrc` argument to `send_rtp/3` overrides `%Rtp{}.ssrc` when they differ
  (Echo v1 passes the inbound `%Rtp{}` unchanged so both match).

  ## Handler callbacks

    * `{:xgw, :ice_connected, peer_ref}`
    * `{:xgw, :local_candidate, peer_ref, %{candidate: line, mid: mid}}` (full mode srflx trickle)
    * `{:xgw, :local_candidates_complete, peer_ref}` (full mode; post-apply gather finished)
    * `{:xgw, :dtls_connected, peer_ref}`
    * `{:xgw, :sctp_connected, peer_ref}` (when offer/answer include SCTP)
    * `{:xgw, :sctp_disconnected, peer_ref}` (SCTP association went down)
    * `{:xgw, :datachannel, peer_ref, %{ref: ref, label: label, id: id}}`
      (optional `:reliability`, `:order`, `:param` from DCEP when present)
    * `{:xgw, :datachannel_closed, peer_ref, channel_ref}`
    * `{:xgw, :datachannel_message, peer_ref, channel_ref, binary()}`
    * `{:xgw, :rtp, peer_ref, %XMediaLib.Rtp{}, meta}`
    * `{:xgw, :rtcp, peer_ref, rtcp, meta}`
    * `{:xgw, :closed, peer_ref, reason}` (`:normal`, `:fingerprint_mismatch`, `:consent_failed`)

  After DTLS, reply on a data channel with `XGW.Peer.send_datachannel/3`.
  Production SCTP and DTLS app-data run on a linked `XGW.Peer.Datachannel`
  child so ICE/RTP on this GenServer are not head-of-line blocked by DC egress.

  ## ICE modes and gather

  Embed host (and optionally srflx) `a=candidate:` lines from
  `XGW.Listener.gather_candidates/2` or `host_candidate_lines/1` in the local
  answer before `apply_descriptions/4`. Post-answer srflx arrives via
  `{:xgw, :local_candidate, ...}` when `stun_servers` is configured.

  Set `ice_lite: false` for the full ICE agent (`XGW.ICE.Full`). Full mode
  parses local host candidates from the answer, stays in `:gathering` until
  srflx, then `:checking` / `:connected` after nomination. Query locals with
  `local_candidates/1` and phase with `ice_phase/1` (`:completed` for lite).

  Gather options (`:advertised_ip`, `:advertised_ips`, `:include_loopback`,
  `:relay_only`) belong on `XGW.Listener.start_link/1`, not the Peer.

  Internal helpers (GenServer stays here):

      Peer.Gather  -- local candidate verify + post-apply srflx/relay gather
      Peer.Turn    -- TURN allocations, unwrap, channel bind, relay encode
      Peer.Sctp    -- SCTP start + event fan-out

  Media callback `meta` map:

    * `:from` - `{ip, port}` of the remote UDP endpoint (ICE-selected pair)
    * `:mid` - BUNDLE m-line id from offer SSRC map, or `nil` when unknown
    * `:arrival_us` - monotonic microseconds when the Listener demuxed the
      packet (wire side). `Peer.deliver/4` fills this only when missing (tests /
      direct inject). Conference TWCC uses it so Peer and Forwarder mailbox
      delay are not reported as network delay.

  ## RFCs

  End-to-end peer stack: RFC 8445 (ICE), RFC 8489 (STUN), RFC 8656 (TURN),
  RFC 9147 / RFC 6347 (DTLS), RFC 5764 (DTLS-SRTP), RFC 3711 (SRTP),
  RFC 8261 / RFC 8831 (SCTP data channels over DTLS), RFC 7675 (consent).
  """

  use GenServer

  require Logger

  alias XGW.{Demux, Descriptions, DTLS, DTLS.Transport, ICE, ICE.Consent, ICE.Full, ICE.Lite, Listener, SRTPSession, TURN.Client}
  alias XGW.Peer.{Datachannel, Gather, Sctp, SendHandle, Turn}
  alias XSockets.Sctp.Association, as: SctpAssociation
  alias XMediaLib.{Rtcp, Rtp}
  alias XMediaLib.SDP.{Candidate, Fingerprint}

  @typedoc "Peer GenServer pid."
  @type peer_ref :: pid()

  @typedoc "Trickle ICE candidate: `%XMediaLib.SDP.Candidate{}` or `%{candidate: line}` map."
  @type candidate :: map()

  @typedoc "Remote offer or local answer as SDP binary or `%XMediaLib.SDP{}`."
  @type sdp :: binary() | struct()

  @typedoc "Connection phase: `:ice_wait`, `:dtls_wait`, `:media`, or `:closed`."
  @type phase :: :ice_wait | :dtls_wait | :media | :closed

  @typedoc "Classified ingress packet kind from `XGW.Demux`."
  @type packet_kind :: XGW.Demux.kind()

  @doc """
  Starts a peer under `XGW.PeerSupervisor`.

  Required: `:handler` (pid). Optional: `:listener`, `:ice_lite` (default `true`;
  `false` selects `XGW.ICE.Full`), `:consent_interval_ms` (default `5000`), `:consent_timeout_ms` (default `30000`),
  `:cert_dir` (unused here; listener owns certs).
  """
  @spec start_link(keyword()) :: {:ok, peer_ref()} | {:error, term()}
  def start_link(opts) when is_list(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Starts a peer as a child of `XGW.PeerSupervisor`.
  """
  @spec start_supervised(keyword()) :: {:ok, peer_ref()} | {:error, term()}
  def start_supervised(opts) when is_list(opts) do
    DynamicSupervisor.start_child(
      XGW.PeerSupervisor,
      %{
        id: {__MODULE__, make_ref()},
        start: {__MODULE__, :start_link, [opts]},
        restart: :temporary,
        type: :worker
      }
    )
  end

  @doc """
  Applies negotiated remote offer and local answer (produced upstream by XSDP).

  Initializes ICE-lite credentials and transport config from `%XMediaLib.SDP{}`
  or SDP binaries. Validates local fingerprint against the listener certificate
  when a listener is attached.
  """
  @spec apply_descriptions(peer_ref(), sdp(), sdp(), keyword()) :: :ok | {:error, term()}
  def apply_descriptions(peer, remote_offer, local_answer, opts \\ []) do
    GenServer.call(peer, {:apply_descriptions, remote_offer, local_answer, opts})
  end

  @doc """
  Adds a remote ICE candidate (Trickle ICE, RFC 8838).

  Accepts `%Candidate{}` or a map with `:candidate` (line or struct), optional
  `:mid`, `:mline_index`, and `:end_of_candidates`.
  """
  @spec add_remote_candidate(peer_ref(), candidate() | Candidate.t()) :: :ok | {:error, term()}
  def add_remote_candidate(peer, candidate) do
    GenServer.call(peer, {:add_remote_candidate, candidate})
  catch
    :exit, {:noproc, _} -> {:error, :not_connected}
  end

  @doc """
  Signals ICE restart with a new remote offer (RFC 8445 section 9.1.1.1).

  Full ufrag/pwd rotation and checklist reset: `Full.ice_restart/1` resets state;
  remote credentials come from the restart offer. Local ufrag/pwd unchanged in v1.
  """
  @spec ice_restart(peer_ref(), sdp()) :: :ok | {:error, term()}
  def ice_restart(peer, offer) do
    GenServer.call(peer, {:ice_restart, offer})
  catch
    :exit, {:noproc, _} -> {:error, :not_connected}
  end

  @doc """
  Replaces the process that receives Peer notifications (`:rtp`, lifecycle, ...).

  Used when a Session installs a media forwarder as `handler:` after start, or
  when tests retarget delivery. `handler` must be a live pid.
  """
  @spec set_handler(peer_ref(), pid()) :: :ok | {:error, term()}
  def set_handler(peer, handler) when is_pid(handler) do
    GenServer.call(peer, {:set_handler, handler})
  end

  @doc """
  Returns a hot-path send handle when UDP media is published in ETS.

  Prefer `XGW.Peer.SendHandle.send_rtp/3` for Echo/SFU forwarding. Returns
  `{:error, :not_ready}` before media, or `{:error, :use_genserver}` for ICE-TCP.
  """
  @spec outbound_handle(peer_ref()) ::
          {:ok, SendHandle.t()} | {:error, :not_ready | :use_genserver}
  def outbound_handle(peer) when is_pid(peer), do: SendHandle.fetch(peer)

  @doc """
  Sends plaintext RTP toward the peer (SRTP-encrypted on the wire).

  Requires `:media` phase. On UDP, uses the same ETS encrypt path as
  `SendHandle.send_rtp/3`. Returns `{:error, :not_connected}`,
  `{:error, :no_selected_pair}`, `{:error, :invalid_packet}`, or an SRTP/UDP error.
  """
  @spec send_rtp(peer_ref(), non_neg_integer(), binary() | Rtp.t()) :: :ok | {:error, term()}
  def send_rtp(peer, ssrc, packet) do
    GenServer.call(peer, {:send_rtp, ssrc, packet})
  end

  @doc """
  Queues plaintext RTP toward the peer without waiting for encrypt/send.

  Prefer `outbound_handle/1` + `SendHandle.send_rtp/3` when a handle is available;
  this cast remains a fallback (ICE-TCP, missing handle).
  """
  @spec send_rtp_async(peer_ref(), non_neg_integer(), binary() | Rtp.t()) :: :ok
  def send_rtp_async(peer, ssrc, packet) do
    GenServer.cast(peer, {:send_rtp, ssrc, packet})
  end

  @doc """
  Sends plaintext RTCP toward the peer (SRTCP-encrypted on the wire).

  Same phase and error semantics as `send_rtp/3`.
  """
  @spec send_rtcp(peer_ref(), binary() | Rtcp.t()) :: :ok | {:error, term()}
  def send_rtcp(peer, packet) do
    GenServer.call(peer, {:send_rtcp, packet})
  end

  @doc """
  Sends a DataChannel user message after SCTP is up.

  Routes to `XGW.Peer.Datachannel` when that child is published; otherwise the
  Peer GenServer (tests / pre-attach). `type` is `:string` (PPI 51, default) or
  `:binary` (PPI 53).
  """
  @spec send_datachannel(peer_ref(), reference(), binary(), :string | :binary) ::
          :ok | {:error, term()}
  def send_datachannel(peer, channel_ref, data, type \\ :string)
      when is_reference(channel_ref) and is_binary(data) and type in [:string, :binary] do
    case Datachannel.lookup(peer) do
      {:ok, dc} -> Datachannel.send_datachannel(dc, channel_ref, data, type)
      :error -> GenServer.call(peer, {:send_datachannel, channel_ref, data, type})
    end
  end

  @doc """
  Queues a DataChannel user message without waiting for SCTP/DTLS flush.

  Prefer `XGW.Peer.SendHandle.send_datachannel/3` when a `:dc_passthrough` row
  is published (benches). Production Forwarder fallback casts the per-Peer
  `XGW.Peer.Datachannel` process (batched drain) when published; otherwise the
  Peer GenServer. `type` defaults to `:string` (PPI 51).
  """
  @spec send_datachannel_async(peer_ref(), reference(), binary(), :string | :binary) :: :ok
  def send_datachannel_async(peer, channel_ref, data, type \\ :string)
      when is_reference(channel_ref) and is_binary(data) and type in [:string, :binary] do
    case Datachannel.lookup(peer) do
      {:ok, dc} -> Datachannel.send_datachannel_async(dc, channel_ref, data, type)
      :error -> GenServer.cast(peer, {:send_datachannel, channel_ref, data, type})
    end
  end

  @doc """
  Opens a local data channel (DCEP) after the SCTP association is connected.

  Synthesizes `{:xgw, :datachannel, peer, info}` to the handler so Session /
  Backend register the label the same way as a remote open. Returns
  `{:error, :not_connected}` when SCTP is missing or not connected.
  """
  @spec open_datachannel(peer_ref(), binary(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def open_datachannel(peer, label, opts \\ [])
      when is_binary(label) and label != "" and is_list(opts) do
    case Datachannel.lookup(peer) do
      {:ok, dc} -> Datachannel.open_datachannel(dc, label, opts)
      :error -> GenServer.call(peer, {:open_datachannel, label, opts})
    end
  end

  @doc """
  Tears down ICE/DTLS and stops the peer process.
  """
  @spec close(peer_ref()) :: :ok | {:error, term()}
  def close(peer) do
    GenServer.call(peer, :close)
  catch
    :exit, {:noproc, _} -> :ok
    :exit, :shutdown -> :ok
    :exit, {:shutdown, _} -> :ok
    :exit, {:timeout, _} -> :ok
  end

  @doc """
  Returns the ICE agent phase.

  Lite peers report `:completed` (binding-only path). Full peers report the
  ICE state machine phase from `XGW.ICE.Full` (for example `:gathering`).
  """
  @spec ice_phase(peer_ref()) :: XGW.ICE.ice_phase()
  def ice_phase(peer), do: GenServer.call(peer, :ice_phase)

  @doc """
  Returns local ICE candidates stored in the full ICE agent.

  Lite peers return `[]`; use `XGW.Listener.host_candidate/1` for lite host lines.
  """
  @spec local_candidates(peer_ref()) :: [Candidate.t()]
  def local_candidates(peer), do: GenServer.call(peer, :local_candidates)

  @doc """
  Allocates TURN relay candidates once and keeps the allocations on the peer.

  Used by relay-only answer builders so `apply_descriptions/3` can seed those
  relay locals without a second Allocate on the same 5-tuple.
  """
  @spec prefetch_relay_candidates(peer_ref()) ::
          {:ok, [String.t()]} | {:error, :no_relay_candidates | term()}
  def prefetch_relay_candidates(peer),
    do: GenServer.call(peer, :prefetch_relay_candidates, 15_000)

  @doc """
  Returns the Peer's media phase (`:ice_wait`, `:dtls_wait`, `:media`, `:closed`).
  """
  @spec phase(peer_ref()) :: phase()
  def phase(peer), do: GenServer.call(peer, :phase)

  @doc """
  Delivers a demuxed packet from the Listener (STUN, DTLS, RTP, RTCP, ChannelData).

  Fills `:arrival_us` on `meta` when missing. The Listener stamps this at demux
  time; this fallback covers tests and any inject path that skips the Listener.
  """
  @spec deliver(peer_ref(), packet_kind(), binary(), map()) :: :ok
  def deliver(peer, kind, data, meta) when is_map(meta) do
    meta =
      if is_integer(Map.get(meta, :arrival_us)) do
        meta
      else
        Map.put(meta, :arrival_us, System.monotonic_time(:microsecond))
      end

    GenServer.cast(peer, {:packet, kind, data, meta})
  end

  @doc """
  Test helper: force ICE connected with optional selected `from` endpoint.
  """
  @spec connect_ice(peer_ref(), {:inet.ip_address(), :inet.port_number()} | nil) :: :ok
  def connect_ice(peer, from \\ nil), do: GenServer.call(peer, {:connect_ice, from})

  @doc """
  Test helper: install SRTP keys and enter media phase (skips live DTLS).
  """
  @spec connect_dtls(peer_ref(), SRTPSession.keys(), {:inet.ip_address(), :inet.port_number()} | nil) ::
          :ok
  def connect_dtls(peer, keys, from \\ nil), do: GenServer.call(peer, {:connect_dtls, keys, from})

  @impl true
  def init(opts) do
    handler = Keyword.fetch!(opts, :handler)
    listener = Keyword.get(opts, :listener)
    ice_lite = Keyword.get(opts, :ice_lite, true)
    consent_interval_ms = Keyword.get(opts, :consent_interval_ms, 5_000)
    consent_timeout_ms = Keyword.get(opts, :consent_timeout_ms, 30_000)

    listener_mon =
      if listener do
        :ok = Listener.register_peer(listener, self())
        Process.monitor(listener)
      end

    ice =
      if ice_lite do
        Lite.new(remote_ice_ufrag: Keyword.get(opts, :remote_ice_ufrag))
      else
        Full.new([])
      end

    {:ok,
     %{
       handler: handler,
       listener: listener,
       listener_mon: listener_mon,
       ice_lite: ice_lite,
       ice: ice,
       phase: :ice_wait,
       remote_offer: nil,
       local_answer: nil,
       config: nil,
       ssrc_to_mid: %{},
       selected: nil,
       selected_transport: :udp,
       selected_tcp: nil,
       ice_ok_remotes: MapSet.new(),
       ssl_sock: nil,
       dtls_task: nil,
       srtp: nil,
       sctp: nil,
       datachannel: nil,
       consent_interval_ms: consent_interval_ms,
       consent_timeout_ms: consent_timeout_ms,
       consent_timer: nil,
       srflx_task: nil,
       relay_task: nil,
       turn_allocations: [],
       turn_channels: %{},
       peer_channels: %{},
       next_turn_channel: 0x4000,
       turn_refresh_timer: nil,
       check_timer: nil,
       pending_dtls: [],
       local_gather_complete?: false,
       closed?: false
     }}
  end

  @impl true
  def handle_call({:apply_descriptions, remote_offer, local_answer, _opts}, _from, state) do
    with {:ok, config} <-
           Descriptions.build(remote_offer, local_answer, ice_lite: state.ice_lite),
         :ok <- verify_local_fingerprint(state.listener, config.local_fingerprint),
         :ok <- Gather.verify_local_candidates(state, config),
         {:ok, ice} <- ice_from_config(state, config) do
      config = %{config | remote_candidates: ice.remote_candidates}

      state =
        state
        |> invalidate_send_handle()
        |> reset_active_session()
        |> Turn.maybe_delete_allocations(config)
        |> Map.merge(%{
          remote_offer: remote_offer,
          local_answer: local_answer,
          config: config,
          ssrc_to_mid: config.ssrc_to_mid,
          ice: ice,
          phase: :ice_wait,
          selected: nil,
          ice_ok_remotes: MapSet.new(),
          local_gather_complete?: false,
          pending_dtls: []
        })
        |> bind_listener_ufrag()
        |> Gather.start_post_apply_srflx()
        |> Gather.start_post_apply_relay()
        |> maybe_start_full_checking()
        |> maybe_prime_dtls_accept()
        |> Gather.maybe_emit_local_candidates_complete()

      {:reply, :ok, state}
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:add_remote_candidate, _candidate}, _from, %{phase: :closed} = state) do
    {:reply, {:error, :not_connected}, state}
  end

  def handle_call({:add_remote_candidate, _candidate}, _from, %{config: nil} = state) do
    {:reply, {:error, :not_connected}, state}
  end

  def handle_call({:add_remote_candidate, candidate}, _from, state) do
    cond do
      state.ice_lite and state.ice ->
        case Lite.add_remote_candidate(state.ice, candidate_info(candidate)) do
          {:ok, ice} ->
            config = %{state.config | remote_candidates: ice.remote_candidates}
            {:reply, :ok, %{state | ice: ice, config: config}}

          {:error, _} = err ->
            {:reply, err, state}
        end

      not state.ice_lite and state.ice ->
        case Full.add_remote_candidate(state.ice, candidate_info(candidate)) do
          {:ok, ice} ->
            config = %{state.config | remote_candidates: ice.remote_candidates}
            {:reply, :ok, schedule_check_tick(%{state | ice: ice, config: config})}

          {:error, _} = err ->
            {:reply, err, state}
        end

      true ->
        {:reply, {:error, :not_connected}, state}
    end
  end

  def handle_call({:ice_restart, _offer}, _from, %{phase: :closed} = state) do
    {:reply, {:error, :not_connected}, state}
  end

  def handle_call({:ice_restart, offer}, _from, %{ice_lite: false, ice: ice, config: config} = state)
      when not is_nil(ice) and not is_nil(config) do
    with {:ok, remote} <- Descriptions.restart_remote(offer) do
      ice =
        ice
        |> Full.ice_restart()
        |> Map.merge(%{
          remote_ice_ufrag: remote.remote_ice_ufrag,
          remote_ice_pwd: remote.remote_ice_pwd,
          remote_candidates: remote.remote_candidates,
          remote_candidates_eoc?: false
        })

      config = %{
        config
        | remote_candidates: remote.remote_candidates,
          ice: Map.merge(config.ice, %{
            remote_ufrag: remote.remote_ice_ufrag,
            remote_pwd: remote.remote_ice_pwd
          })
      }

      state =
        state
        |> invalidate_send_handle()
        |> reset_active_session()
        |> Turn.delete_allocations()
        |> Map.merge(%{
          phase: :ice_wait,
          selected: nil,
          ice_ok_remotes: MapSet.new(),
          ice: ice,
          config: config,
          remote_offer: offer,
          local_gather_complete?: false,
          srtp: nil,
          ssl_sock: nil,
          pending_dtls: []
        })
        |> Gather.start_post_apply_srflx()
        |> Gather.start_post_apply_relay()
        |> maybe_start_full_checking()
        |> Gather.maybe_emit_local_candidates_complete()

      {:reply, :ok, state}
    else
      {:error, _} = err -> {:reply, err, state}
    end
  end

  def handle_call({:ice_restart, _offer}, _from, state) do
    {:reply, {:error, :not_implemented}, state}
  end

  def handle_call({:set_handler, handler}, _from, state) when is_pid(handler) do
    {:reply, :ok, %{state | handler: handler}}
  end

  def handle_call({:send_rtp, ssrc, packet}, _from, state) do
    {reply, state} = do_send_rtp(state, ssrc, packet)
    {:reply, reply, state}
  end

  def handle_call({:send_rtcp, packet}, _from, %{phase: :media, srtp: srtp} = state)
      when not is_nil(srtp) do
    with {:ok, rtcp} <- normalize_rtcp(packet),
         {:ok, wire, srtp2} <- SRTPSession.encrypt(srtp, :rtcp, rtcp),
         :ok <- send_wire(state, wire) do
      {:reply, :ok, %{state | srtp: srtp2}}
    else
      {:error, %SRTPSession{} = srtp2} ->
        {:reply, {:error, :encrypt_failed}, %{state | srtp: srtp2}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}

      _ ->
        {:reply, {:error, :invalid_packet}, state}
    end
  end

  def handle_call({:send_rtcp, _packet}, _from, state) do
    {:reply, {:error, :not_connected}, state}
  end

  def handle_call({:send_datachannel, channel_ref, data}, _from, state) do
    {reply, state} = do_send_datachannel(state, channel_ref, data, :string)
    {:reply, reply, state}
  end

  def handle_call({:send_datachannel, channel_ref, data, type}, _from, state)
      when type in [:string, :binary] do
    {reply, state} = do_send_datachannel(state, channel_ref, data, type)
    {:reply, reply, state}
  end

  def handle_call({:open_datachannel, label, opts}, _from, state)
      when is_binary(label) and is_list(opts) do
    {reply, state} = do_open_datachannel(state, label, opts)
    {:reply, reply, state}
  end

  def handle_call(:phase, _from, state) do
    {:reply, state.phase, state}
  end

  def handle_call(:ice_phase, _from, %{ice_lite: true} = state) do
    {:reply, :completed, state}
  end

  def handle_call(:ice_phase, _from, %{ice: ice} = state) when not is_nil(ice) do
    {:reply, Full.phase(ice), state}
  end

  def handle_call(:ice_phase, _from, state) do
    {:reply, :gathering, state}
  end

  def handle_call(:local_candidates, _from, %{ice_lite: false, ice: ice} = state)
      when not is_nil(ice) do
    {:reply, ice.local_candidates, state}
  end

  def handle_call(:local_candidates, _from, state) do
    {:reply, [], state}
  end

  def handle_call(:prefetch_relay_candidates, _from, %{listener: nil} = state) do
    {:reply, {:error, :no_relay_candidates}, state}
  end

  def handle_call(:prefetch_relay_candidates, _from, state) do
    state = Turn.delete_allocations(state)
    results = Turn.gather_relay(state)

    case results do
      [] ->
        {:reply, {:error, :no_relay_candidates}, state}

      results ->
        lines = Enum.map(results, fn %{candidate: c} -> ICE.candidate_line(c) end)
        allocs = Enum.map(results, & &1.allocation)

        {:reply, {:ok, lines},
         Turn.schedule_refresh_tick(%{state | turn_allocations: allocs})}
    end
  end

  def handle_call({:connect_ice, from}, _from, state) do
    selected = from || state.selected || {{127, 0, 0, 1}, 0}

    ice =
      case state.ice do
        %{connected?: _} = ice ->
          ice
          |> Map.put(:connected?, true)
          |> Map.put(:selected, selected)

        other ->
          other
      end

    state =
      %{state | ice: ice, selected: selected}
      |> remember_ice_remote(selected)
      |> ice_connected(selected)

    {:reply, :ok, state}
  end

  def handle_call({:connect_dtls, keys, from}, _from, state) do
    state = if from, do: %{state | selected: from}, else: state
    state = dtls_connected(state, keys)
    {:reply, :ok, state}
  end

  def handle_call(:close, _from, state) do
    state = do_close(state, :normal)
    {:stop, :normal, :ok, state}
  end

  @impl true
  def handle_cast({:send_rtp, ssrc, packet}, state) do
    {_reply, state} = do_send_rtp(state, ssrc, packet)
    {:noreply, state}
  end

  def handle_cast({:send_datachannel, channel_ref, data}, state) do
    {_reply, state} = do_send_datachannel(state, channel_ref, data, :string)
    {:noreply, state}
  end

  def handle_cast({:send_datachannel, channel_ref, data, type}, state)
      when type in [:string, :binary] do
    {_reply, state} = do_send_datachannel(state, channel_ref, data, type)
    {:noreply, state}
  end

  def handle_cast({:packet, kind, data, meta}, state) do
    state = route_packet(state, kind, data, meta)
    {:noreply, state}
  end

  @impl true
  def handle_info({ref, srflx}, %{srflx_task: %Task{ref: ref}} = state) when is_list(srflx) do
    Process.demonitor(ref, [:flush])

    state =
      %{state | srflx_task: nil}
      |> Gather.apply_srflx_candidates(srflx)
      |> then(&schedule_check_tick/1)

    {:noreply, Gather.maybe_emit_local_candidates_complete(state)}
  end

  def handle_info({ref, relay_results}, %{relay_task: %Task{ref: ref}} = state) when is_list(relay_results) do
    Process.demonitor(ref, [:flush])

    state =
      %{state | relay_task: nil}
      |> Turn.apply_relay_results(relay_results)
      |> then(&schedule_check_tick/1)

    {:noreply, Gather.maybe_emit_local_candidates_complete(state)}
  end

  def handle_info({:DOWN, ref, :process, _pid, :normal}, %{srflx_task: %Task{ref: ref}} = state) do
    # Successful Tasks also emit DOWN; wait for `{ref, result}` (demonitor flushes this).
    {:noreply, state}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{srflx_task: %Task{ref: ref}} = state) do
    state = %{state | srflx_task: nil} |> Gather.maybe_emit_local_candidates_complete()
    {:noreply, state}
  end

  def handle_info({:DOWN, ref, :process, _pid, :normal}, %{relay_task: %Task{ref: ref}} = state) do
    {:noreply, state}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{relay_task: %Task{ref: ref}} = state) do
    state = %{state | relay_task: nil} |> Gather.maybe_emit_local_candidates_complete()
    {:noreply, state}
  end

  def handle_info(:turn_refresh_tick, state) do
    {:noreply, state |> Turn.refresh_allocations() |> Turn.schedule_refresh_tick()}
  end

  def handle_info(:ice_check_tick, %{closed?: true} = state) do
    {:noreply, cancel_check_timer(state)}
  end

  def handle_info(:ice_check_tick, %{ice_lite: false, ice: ice} = state) when not is_nil(ice) do
    unless listener_alive?(state.listener) do
      {:noreply, cancel_check_timer(state)}
    else
      now = System.monotonic_time(:millisecond)

      case Full.tick(ice, now) do
        {:noop, ice} ->
          {:noreply, schedule_check_tick(%{state | ice: ice})}

        {:send, wire, dest, ice, _tid} ->
          _ = send_check_wire(state, ice, wire, dest)
          {:noreply, schedule_check_tick(%{state | ice: ice})}
      end
    end
  end

  def handle_info(:ice_check_tick, state), do: {:noreply, state}

  def handle_info({:xgw_internal, :dtls_ready, ssl_sock, export_result}, state) do
    state = %{state | ssl_sock: ssl_sock}

    state =
      case export_result do
        {:ok, keys} ->
          dtls_connected(state, keys)

        other ->
          Logger.error("xgw DTLS SRTP key export failed: #{inspect(other)}")
          state
      end

    {:noreply, state}
  end

  def handle_info({:ssl, _ssl_sock, data}, %{ssl_sock: sock, sctp: assoc} = state)
      when not is_nil(sock) and not is_nil(assoc) do
    _ = :ssl.setopts(sock, mode: :binary, active: :once)

    try do
      bin = IO.iodata_to_binary(data)
      Logger.debug("xgw peer DTLS app data #{byte_size(bin)} bytes")
      {events, assoc} = SctpAssociation.handle_packet(assoc, bin)
      {:noreply, Sctp.flush_events(%{state | sctp: assoc}, events, &send_dtls_app/2)}
    rescue
      ArgumentError ->
        Logger.warning("xgw peer ignored non-iodata ssl payload: #{inspect(data)}")
        {:noreply, state}
    end
  end

  def handle_info({:ssl, _ssl_sock, _data}, %{ssl_sock: sock} = state) when not is_nil(sock) do
    _ = :ssl.setopts(sock, mode: :binary, active: :once)
    {:noreply, state}
  end

  def handle_info({:ssl_closed, _ssl_sock}, %{ssl_sock: sock} = state) when not is_nil(sock) do
    state = stop_datachannel(%{state | ssl_sock: nil, sctp: nil})
    {:noreply, state}
  end

  def handle_info({:ssl_error, _ssl_sock, reason}, %{ssl_sock: sock} = state)
      when not is_nil(sock) do
    Logger.warning("xgw peer ssl error: #{inspect(reason)}")
    {:noreply, state}
  end

  def handle_info({:xgw_internal, :datachannel_down, dc, _reason}, %{datachannel: dc} = state) do
    {:noreply, %{state | datachannel: nil, sctp: nil}}
  end

  def handle_info({:xgw_internal, :datachannel_down, _dc, _reason}, state) do
    {:noreply, state}
  end

  # If transport ownership was ever stolen, DTLS records land here instead of :ssl.
  def handle_info({:udp, _socket, _ip, _port, data}, state) when is_binary(data) do
    Logger.warning(
      "xgw peer received raw UDP DTLS inject (#{byte_size(data)} bytes); transport owner misconfigured"
    )

    {:noreply, state}
  end

  def handle_info(:sctp_timeout, %{sctp: assoc} = state) when not is_nil(assoc) do
    {events, assoc} = SctpAssociation.handle_timeout(assoc)
    {:noreply, Sctp.flush_events(%{state | sctp: assoc}, events, &send_dtls_app/2)}
  end

  def handle_info(:sctp_timeout, state), do: {:noreply, state}

  def handle_info({:xgw_internal, :dtls_fingerprint_mismatch}, state) do
    state = do_close(state, :fingerprint_mismatch)
    {:stop, :normal, state}
  end

  def handle_info({:xgw_internal, :dtls_error, reason}, state) do
    Logger.warning("xgw peer DTLS error: #{inspect(reason)}")
    {:noreply, state}
  end

  def handle_info(:consent_tick, %{phase: :media, ice: ice} = state) when not is_nil(ice) do
    now = System.monotonic_time(:millisecond)

    if Consent.expired?(ice, now, state.consent_timeout_ms) do
      state = cancel_consent_timer(do_close(state, :consent_failed))
      {:stop, :normal, state}
    else
      state = maybe_send_consent_binding(state)
      {:noreply, schedule_consent_tick(state)}
    end
  end

  def handle_info(:consent_tick, state), do: {:noreply, state}

  def handle_info(
        {:DOWN, ref, :process, _pid, _reason},
        %{listener_mon: ref} = state
      ) do
    _ = SendHandle.invalidate(self())
    state = do_close(%{state | listener: nil, listener_mon: nil}, :listener_down)
    {:stop, :normal, state}
  end

  @impl true
  def terminate(reason, state) do
    _ = do_close(state, terminate_close_reason(reason))
    :ok
  end

  defp terminate_close_reason(:normal), do: :normal
  defp terminate_close_reason(:shutdown), do: :normal
  defp terminate_close_reason(reason), do: reason

  defp route_packet(%{phase: :closed} = state, _kind, _data, _meta), do: state

  defp route_packet(state, :turn_channel, data, meta) do
    case Client.decode_channel_data(data) do
      {:ok, channel, inner} ->
        case Map.get(state.turn_channels, channel) do
          nil ->
            state

          peer_from ->
            case Demux.classify_kind(inner) do
              {:ok, inner_kind} ->
                route_packet(state, inner_kind, inner, %{meta | from: peer_from})

              _ ->
                state
            end
        end

      :error ->
        state
    end
  end

  defp route_packet(state, :stun, data, meta) do
    case Turn.unwrap_data_indication(data) do
      {:ok, inner, peer_from} ->
        case Demux.classify_kind(inner) do
          {:ok, inner_kind} ->
            route_packet(state, inner_kind, inner, %{meta | from: peer_from})

          _ ->
            state
        end

      :not_turn_data ->
        if state.ice do
          from = Map.fetch!(meta, :from)
          handle_stun(state, data, from, meta)
        else
          state
        end
    end
  end

  defp route_packet(%{phase: :ice_wait} = state, :dtls, data, meta) do
    from = Map.get(meta, :from)
    pending = state.pending_dtls ++ [{data, from}]
    %{state | pending_dtls: pending}
  end

  defp route_packet(%{phase: phase} = state, :dtls, data, meta)
       when phase in [:dtls_wait, :media] do
    if state.listener && dtls_from_ok?(state, meta) do
      {ip, port} = Map.fetch!(meta, :from)
      Logger.debug("xgw peer DTLS inject phase=#{phase} from=#{inspect({ip, port})} bytes=#{byte_size(data)}")
      udp = Listener.udp_sock(state.listener)
      _ = Transport.set_inject_owner(udp, {ip, port})
      Transport.inject(udp, ip, port, data)
    else
      Logger.debug(
        "xgw peer DTLS dropped phase=#{phase} selected=#{inspect(state.selected)} from=#{inspect(Map.get(meta, :from))}"
      )
    end

    state
  end

  defp route_packet(%{phase: :media, srtp: srtp} = state, kind, data, meta)
       when kind in [:rtp, :rtcp] and not is_nil(srtp) do
    if ice_selected?(state, meta) do
      t0 = System.monotonic_time(:microsecond)

      case SRTPSession.decrypt(srtp, kind, data) do
        {:ok, plaintext, srtp2} ->
          meta = enrich_media_meta(state, meta, kind, plaintext)
          send(state.handler, {:xgw, kind, self(), plaintext, meta})

          if kind == :rtp and System.get_env("XYLON_RTP_PROFILE") in ["1", "true", "yes"] and
               :erlang.phash2(t0, 50) == 0 do
            mb =
              case Process.info(self(), :message_queue_len) do
                {:message_queue_len, n} -> n
                _ -> -1
              end

            Logger.debug(
              "xgw rtp in decrypt_us=#{System.monotonic_time(:microsecond) - t0} mb=#{mb} bytes=#{byte_size(data)}"
            )
          end

          %{state | srtp: srtp2}

        {:error, srtp2} ->
          %{state | srtp: srtp2}
      end
    else
      state
    end
  end

  defp route_packet(state, _kind, _data, _meta), do: state

  # Once ICE has a selected pair, accept DTLS from that endpoint.
  # ICE-TCP requires an exact socket peername match (ephemeral port).
  defp dtls_from_ok?(%{selected: nil}, _meta), do: true

  defp dtls_from_ok?(%{selected_transport: :tcp, selected: selected}, %{from: from}),
    do: selected == from

  defp dtls_from_ok?(%{selected: {sip, _sport}}, %{from: {fip, _fport}}) when sip == fip,
    do: true

  defp dtls_from_ok?(state, meta), do: ice_selected?(state, meta)


  defp handle_stun(%{ice_lite: false, ice: ice} = state, data, from, meta) do
    opts = [transport: Map.get(meta, :transport, :udp)]

    case Full.handle_stun(data, from, ice, opts) do
      {:consent, ice} ->
        %{state | ice: ice}

      {:ignore, ice} ->
        state |> Map.put(:ice, ice) |> refresh_consent_if_media(from)

      {:reply, reply, ice} ->
        send_stun_reply(state, from, meta, reply)

        state
        |> Map.put(:ice, ice)
        |> refresh_consent_if_media(from)
        |> schedule_check_tick()

      {:connected, reply, ice, selected} ->
        send_stun_reply(state, from, meta, reply)

        state =
          state
          |> Map.put(:ice, ice)
          |> Turn.maybe_create_permission(ice)
          |> cancel_check_timer()

        ice_connected(state, selected, meta)
    end
  end

  defp handle_stun(%{ice_lite: true, ice: ice} = state, data, from, _meta) do
    case Lite.handle_binding(data, from, ice) do
      {:connected, reply, ice} ->
        if state.listener, do: Listener.send(state.listener, elem(from, 0), elem(from, 1), reply)
        ice = maybe_refresh_consent(ice, from, state)

        state =
          state
          |> Map.put(:ice, ice)
          |> remember_ice_remote(from)

        # First connectivity check selects the pair; later spurious :connected must not flip it.
        if state.phase == :ice_wait do
          ice_connected(%{state | selected: from}, from)
        else
          state
        end

      {:reply, reply, ice} ->
        if state.listener, do: Listener.send(state.listener, elem(from, 0), elem(from, 1), reply)
        ice = maybe_refresh_consent(ice, from, state)

        # Do not flip the outbound selected pair on every check (multi-homed Chrome).
        # Still accept inbound media from every validated remote.
        state =
          state
          |> Map.put(:ice, ice)
          |> remember_ice_remote(from)
          |> maybe_adopt_nominated_selected(ice)

        state

      {:consent, ice} ->
        ice = maybe_refresh_consent(ice, from, state)
        %{state | ice: ice} |> remember_ice_remote(from)

      {:ignore, _} ->
        state
    end
  end

  defp ice_connected(state, from, meta \\ %{})

  defp ice_connected(%{phase: :ice_wait} = state, from, meta) do
    send(state.handler, {:xgw, :ice_connected, self()})

    ice =
      if state.ice_lite or is_nil(state.ice) do
        state.ice
      else
        Full.mark_completed(state.ice)
      end

    transport = Map.get(meta, :transport, :udp)
    tcp_sock = Map.get(meta, :tcp_sock)

    state = %{
      state
      | phase: :dtls_wait,
        selected: from,
        selected_transport: transport,
        selected_tcp: tcp_sock,
        ice: ice
    }

    state
    |> maybe_arm_dtls_relay_send()
    |> maybe_arm_dtls_tcp_send()
    |> maybe_arm_dtls_inject_owner()
    |> maybe_start_dtls()
    |> flush_pending_dtls()
  end

  defp ice_connected(state, _from, _meta), do: state

  defp maybe_arm_dtls_inject_owner(%{listener: listener, selected: remote} = state)
       when is_pid(listener) and not is_nil(remote) do
    _ = Transport.set_inject_owner(Listener.udp_sock(listener), remote)
    state
  end

  defp maybe_arm_dtls_inject_owner(state), do: state

  defp maybe_arm_dtls_tcp_send(
         %{listener: listener, selected_transport: :tcp, selected_tcp: tcp_sock, selected: peer} =
           state
       )
       when is_pid(listener) and is_port(tcp_sock) and not is_nil(peer) do
    udp = Listener.udp_sock(listener)
    _ = Transport.set_tcp_send(udp, tcp_sock, peer)
    Logger.info("xgw peer armed DTLS ICE-TCP send to=#{inspect(peer)}")
    state
  end

  defp maybe_arm_dtls_tcp_send(state), do: state

  defp maybe_arm_dtls_relay_send(%{listener: listener, selected: peer} = state)
       when is_pid(listener) and not is_nil(peer) do
    case Turn.relay_send_allocation(state) do
      nil ->
        state

      alloc ->
        udp = Listener.udp_sock(listener)
        channel = Map.get(state.peer_channels, peer)
        _ = Transport.set_relay_send(udp, alloc, peer, channel: channel)
        Logger.info("xgw peer armed DTLS relay send to=#{inspect(peer)} channel=#{inspect(channel)}")
        publish_send_handle(state)
    end
  end

  defp maybe_arm_dtls_relay_send(state), do: state

  defp send_stun_reply(_state, _from, _meta, <<>>), do: :ok

  defp send_stun_reply(%{listener: listener}, from, %{transport: :tcp}, reply) when is_pid(listener) do
    _ = Listener.send_tcp_stun(listener, from, reply)
  end

  defp send_stun_reply(%{listener: listener} = state, {ip, port} = from, _meta, reply)
       when is_pid(listener) do
    case Turn.relay_send_allocation(state) do
      nil ->
        Listener.send(listener, ip, port, reply)

      alloc ->
        send_recv = fn wire, {tip, tport} ->
          Listener.turn_request(listener, tip, tport, Listener.gather_timeout_ms(listener), wire)
        end

        _ = Client.create_permission(send_recv, alloc, from)

        if channel = Map.get(state.peer_channels, from) do
          _ = Client.channel_bind(send_recv, alloc, from, channel)
        end

        payload = Turn.encode_relay_app_data(state, alloc, from, reply)

        send_datagram_safe(
          listener,
          elem(alloc.turn_server, 0),
          elem(alloc.turn_server, 1),
          payload
        )
    end
  end

  defp send_stun_reply(_, _, _, _), do: :ok


  # Prime accept as soon as SDP is applied (full ICE) so OTP owns the Transport
  # before the browser's first DTLS flight arrives via TURN.
  defp maybe_prime_dtls_accept(%{ice_lite: true} = state), do: state
  defp maybe_prime_dtls_accept(%{dtls_task: task} = state) when not is_nil(task), do: state

  defp maybe_prime_dtls_accept(%{listener: listener, config: config} = state)
       when is_pid(listener) and not is_nil(config) do
    listen_sock = Listener.listen_sock(listener)

    {:ok, task} =
      DTLS.start_accept(listen_sock, self(),
        expected_fingerprint: config.remote_fingerprint
      )

    %{state | dtls_task: task}
  end

  defp maybe_prime_dtls_accept(state), do: state

  defp maybe_start_dtls(%{listener: listener, phase: :dtls_wait, dtls_task: nil, config: config} = state)
       when is_pid(listener) and not is_nil(config) do
    listen_sock = Listener.listen_sock(listener)

    {:ok, task} =
      DTLS.start_accept(listen_sock, self(),
        expected_fingerprint: config.remote_fingerprint
      )

    %{state | dtls_task: task}
  end

  defp maybe_start_dtls(%{dtls_task: _} = state), do: state

  defp maybe_start_dtls(state), do: state

  defp flush_pending_dtls(%{pending_dtls: []} = state), do: state

  defp flush_pending_dtls(%{pending_dtls: pending, listener: listener} = state)
       when is_pid(listener) do
    udp = Listener.udp_sock(listener)

    Enum.each(pending, fn {data, from} ->
      if from do
        {ip, port} = from
        _ = Transport.set_inject_owner(udp, {ip, port})
        Transport.inject(udp, ip, port, data)
      end
    end)

    %{state | pending_dtls: []}
  end

  defp flush_pending_dtls(state), do: %{state | pending_dtls: []}
  defp dtls_connected(%{phase: phase} = state, keys) when phase in [:dtls_wait, :media] do
    unless phase == :media do
      send(state.handler, {:xgw, :dtls_connected, self()})
    end

    state
    |> Map.put(:phase, :media)
    |> Map.put(:srtp, SRTPSession.new(keys))
    |> maybe_attach_datachannel()
    |> start_consent()
    |> maybe_arm_dtls_relay_send()
    |> publish_send_handle()
  end

  defp dtls_connected(state, _keys), do: state

  defp maybe_attach_datachannel(%{config: %{sctp: sctp}, ssl_sock: sock, datachannel: nil} = state)
       when not is_nil(sctp) and not is_nil(sock) do
    if SctpAssociation.available?() do
      case Datachannel.start_link(
             peer: self(),
             handler: state.handler,
             ssl_sock: sock,
             role: :passive,
             sctp_ports: sctp
           ) do
        {:ok, dc} ->
          %{state | datachannel: dc, sctp: nil}

        {:error, reason} ->
          Logger.warning("xgw peer datachannel start failed: #{inspect(reason)}")
          Sctp.maybe_start(state)
      end
    else
      Logger.warning("xgw peer SCTP negotiated but ex_sctp is not loaded")
      state
    end
  end

  defp maybe_attach_datachannel(state), do: state

  defp send_dtls_app(%{ssl_sock: sock}, data) when not is_nil(sock) and is_binary(data) do
    :ssl.send(sock, data)
  end

  defp send_dtls_app(_, _), do: {:error, :no_ssl}

  defp ice_selected?(%{selected: from}, %{from: from}), do: true
  defp ice_selected?(%{selected: nil}, _meta), do: true

  defp ice_selected?(%{ice_ok_remotes: ok}, %{from: from}) when not is_nil(ok) do
    MapSet.member?(ok, from)
  end

  defp ice_selected?(_state, _meta), do: false

  defp remember_ice_remote(%{ice_ok_remotes: ok, listener: listener} = state, from)
       when not is_nil(from) do
    if is_pid(listener) and Process.alive?(listener) do
      _ = Listener.bind_remote(listener, self(), from)
    end

    %{state | ice_ok_remotes: MapSet.put(ok || MapSet.new(), from)}
  end

  defp remember_ice_remote(state, _from), do: state

  defp bind_listener_ufrag(%{listener: listener, ice: ice} = state)
       when is_pid(listener) and not is_nil(ice) do
    ufrag = Map.get(ice, :ice_ufrag)

    if is_binary(ufrag) and ufrag != "" and Process.alive?(listener) do
      _ = Listener.bind_ufrag(listener, self(), ufrag)
    end

    state
  end

  defp bind_listener_ufrag(state), do: state

  # Lite updates ice.selected on USE-CANDIDATE; adopt that for outbound.
  defp maybe_adopt_nominated_selected(%{selected: sel} = state, %{selected: ice_sel})
       when not is_nil(ice_sel) and not is_nil(sel) and ice_sel != sel do
    publish_send_handle(%{state | selected: ice_sel})
  end

  defp maybe_adopt_nominated_selected(%{selected: nil} = state, %{selected: ice_sel})
       when not is_nil(ice_sel) do
    publish_send_handle(%{state | selected: ice_sel})
  end

  defp maybe_adopt_nominated_selected(state, _ice), do: state

  defp do_close(%{closed?: true} = state, _reason), do: state

  defp do_close(state, reason) do
    _ = SendHandle.invalidate(self())
    send(state.handler, {:xgw, :closed, self(), reason})

    if listener = state.listener do
      if Process.alive?(listener) do
        udp = Listener.udp_sock(listener)

        if selected = state.selected do
          _ = Transport.clear_relay_send(udp, selected)
          _ = Transport.clear_tcp_send(udp, selected)
          _ = Transport.clear_inject_owner(udp, selected)
        end
      end

      safe_unregister_peer(listener, self())
    end

    state = stop_datachannel(state)
    if ssl_sock = state.ssl_sock, do: :ssl.close(ssl_sock)
    kill_linked_task(state.dtls_task)
    kill_linked_task(state.srflx_task)
    kill_linked_task(state.relay_task)
    _ = Turn.delete_allocations(state)

    state
    |> cancel_consent_timer()
    |> Turn.cancel_refresh_timer()
    |> cancel_check_timer()
    |> Map.put(:phase, :closed)
    |> Map.put(:closed?, true)
    |> Map.put(:ssl_sock, nil)
    |> Map.put(:srtp, nil)
    |> Map.put(:dtls_task, nil)
    |> Map.put(:turn_allocations, [])
    |> Turn.clear_channels()
  end

  defp stop_datachannel(%{datachannel: dc} = state) when is_pid(dc) do
    if Process.alive?(dc) do
      _ = GenServer.stop(dc, :normal, 5_000)
    end

    %{state | datachannel: nil, sctp: nil}
  catch
    :exit, _ -> %{state | datachannel: nil, sctp: nil}
  end

  defp stop_datachannel(state), do: state

  defp safe_unregister_peer(listener, peer) when is_pid(listener) do
    if Process.alive?(listener) do
      _ = Listener.unregister_peer(listener, peer)
    end

    :ok
  end

  defp listener_alive?(nil), do: false
  defp listener_alive?(listener) when is_pid(listener), do: Process.alive?(listener)

  defp kill_linked_task(nil), do: :ok

  defp kill_linked_task(%Task{} = task) do
    Process.unlink(task.pid)
    Task.shutdown(task, :brutal_kill)
  end

  defp kill_linked_task(pid) when is_pid(pid) do
    Process.unlink(pid)
    _ = Process.exit(pid, :shutdown)
    :ok
  end

  defp start_consent(%{ice: ice} = state) when not is_nil(ice) do
    now = System.monotonic_time(:millisecond)
    state = %{state | ice: Consent.refresh(ice, now)}
    schedule_consent_tick(state)
  end

  defp start_consent(state), do: state

  defp schedule_consent_tick(%{consent_interval_ms: ms} = state) do
    ref = Process.send_after(self(), :consent_tick, ms)
    %{state | consent_timer: ref}
  end

  defp cancel_consent_timer(%{consent_timer: ref} = state) when is_reference(ref) do
    _ = Process.cancel_timer(ref)
    %{state | consent_timer: nil}
  end

  defp cancel_consent_timer(state), do: state

  defp maybe_send_consent_binding(%{listener: listener, selected: {ip, port}, ice: ice} = state)
       when is_pid(listener) and not is_nil(ice) do
    wire = Consent.binding_request(ice)
    _ = Listener.send_datagram(listener, ip, port, wire)
    state
  end

  defp maybe_send_consent_binding(state), do: state

  defp maybe_refresh_consent(ice, from, %{phase: :media, selected: {ip, port}})
       when is_tuple(from) do
    if from == {ip, port} do
      Consent.refresh(ice, System.monotonic_time(:millisecond))
    else
      ice
    end
  end

  defp maybe_refresh_consent(ice, _from, _state), do: ice

  defp refresh_consent_if_media(%{phase: :media, ice: ice} = state, from) do
    %{state | ice: maybe_refresh_consent(ice, from, state)}
  end

  defp refresh_consent_if_media(state, _from), do: state

  defp candidate_info(%Candidate{} = c), do: %{candidate: c}
  defp candidate_info(%{} = m), do: m
  defp candidate_info(_), do: %{invalid: true}

  defp verify_local_fingerprint(nil, _fp), do: :ok

  defp verify_local_fingerprint(listener, %Fingerprint{} = fp) do
    local = Listener.local_fingerprint(listener)

    if Descriptions.normalize_fingerprint(fp.value) ==
         Descriptions.normalize_fingerprint(local) do
      :ok
    else
      {:error, :local_fingerprint_mismatch}
    end
  end

  defp ice_from_config(%{ice_lite: true}, config) do
    {:ok,
     config
     |> Lite.from_config()
     |> Lite.seed_remote_candidates(config.remote_candidates)}
  end

  defp ice_from_config(%{ice_lite: false}, config) do
    with {:ok, ice} <- Full.from_config(config) do
      {:ok,
       ice
       |> Full.seed_remote_candidates(config.remote_candidates)
       |> Full.seed_local_candidates(config.local_candidates)}
    end
  end

  defp reset_active_session(state) do
    state
    |> stop_datachannel()
    |> cancel_check_timer()
    |> cancel_consent_timer()
    |> Turn.cancel_refresh_timer()
    |> shutdown_gather_tasks()
    |> shutdown_dtls_task()
    |> close_ssl_sock()
    |> Map.put(:sctp, nil)
  end

  defp shutdown_gather_tasks(state) do
    state =
      case state.srflx_task do
        %Task{} = task ->
          kill_linked_task(task)
          %{state | srflx_task: nil}

        _ ->
          state
      end

    case state.relay_task do
      %Task{} = task ->
        kill_linked_task(task)
        %{state | relay_task: nil}

      _ ->
        state
    end
  end

  defp shutdown_dtls_task(%{dtls_task: task, listener: listener} = state) when is_pid(task) do
    kill_linked_task(task)
    maybe_reset_dtls_owner(listener)
    %{state | dtls_task: nil}
  end

  defp shutdown_dtls_task(%{dtls_task: %Task{} = task, listener: listener} = state) do
    kill_linked_task(task)
    maybe_reset_dtls_owner(listener)
    %{state | dtls_task: nil}
  end

  defp shutdown_dtls_task(state), do: state

  defp maybe_reset_dtls_owner(listener) when is_pid(listener) do
    if Process.alive?(listener) do
      _ = Transport.reset_owner(Listener.udp_sock(listener))
    end

    :ok
  end

  defp maybe_reset_dtls_owner(_), do: :ok

  defp close_ssl_sock(%{ssl_sock: sock} = state) when not is_nil(sock) do
    :ssl.close(sock)
    %{state | ssl_sock: nil}
  end

  defp close_ssl_sock(state), do: state

  defp maybe_start_full_checking(%{ice_lite: false, ice: ice} = state) when not is_nil(ice) do
    ice = Full.start_checking(ice)
    schedule_check_tick(%{state | ice: ice})
  end

  defp maybe_start_full_checking(state), do: state

  defp schedule_check_tick(%{ice_lite: false, ice: %{phase: :checking}} = state) do
    state = cancel_check_timer(state)
    ref = Process.send_after(self(), :ice_check_tick, Full.check_ta_ms())
    %{state | check_timer: ref}
  end

  defp schedule_check_tick(state), do: state

  defp cancel_check_timer(%{check_timer: ref} = state) when is_reference(ref) do
    _ = Process.cancel_timer(ref)
    %{state | check_timer: nil}
  end

  defp cancel_check_timer(state), do: state

  defp send_check_wire(state, ice, wire, dest) do
    case state do
      %{listener: listener} when is_pid(listener) ->
        if Process.alive?(listener) do
          do_send_check_wire(listener, state, ice, wire, dest)
        else
          :ok
        end

      _ ->
        :ok
    end
  end

  defp do_send_check_wire(listener, state, ice, wire, dest) do
    case Enum.find(ice.checklist, &(&1.state == :in_progress)) do
      %{local: %{transport: t}} when t in ["tcp", "TCP"] ->
        _ = Listener.tcp_connect_stun(listener, dest, wire)

      %{local: %{type: "relay"} = local, remote: remote} ->
        peer = ICE.endpoint(remote)

        case Turn.find_allocation(state, local) do
          nil ->
            Logger.warning(
              "xgw relay check missing allocation local=#{local.ip}:#{local.port} allocs=#{inspect(Enum.map(state.turn_allocations, & &1.relay))}"
            )

            send_datagram_safe(listener, elem(dest, 0), elem(dest, 1), wire)

          alloc ->
            send_recv = fn w, {ip, port} ->
              Listener.turn_request(listener, ip, port, Listener.gather_timeout_ms(listener), w)
            end

            case Client.create_permission(send_recv, alloc, peer) do
              :ok ->
                :ok

              {:error, reason} ->
                Logger.warning(
                  "xgw createperm failed peer=#{inspect(peer)} reason=#{inspect(reason)}"
                )
            end

            # Checklist checks stay on Send Indication; ChannelBind runs after nomination.
            indication = Client.send_indication(alloc, peer, wire)

            send_datagram_safe(
              listener,
              elem(alloc.turn_server, 0),
              elem(alloc.turn_server, 1),
              indication
            )
        end

      _ ->
        send_datagram_safe(listener, elem(dest, 0), elem(dest, 1), wire)
    end
  end

  defp send_datagram_safe(listener, ip, port, wire) when is_pid(listener) do
    if Process.alive?(listener) do
      try do
        Listener.send_datagram(listener, ip, port, wire)
      catch
        :exit, _ -> :ok
      end
    end
  end

  defp enrich_media_meta(state, meta, :rtp, %Rtp{ssrc: ssrc}) do
    Map.put(meta, :mid, Map.get(state.ssrc_to_mid, ssrc))
  end

  defp enrich_media_meta(state, meta, :rtcp, %Rtcp{payloads: [first | _]}) do
    ssrc = Map.get(first, :ssrc)
    Map.put(meta, :mid, if(ssrc, do: Map.get(state.ssrc_to_mid, ssrc)))
  end

  defp enrich_media_meta(_state, meta, _kind, _plaintext), do: meta

  defp normalize_rtp(%Rtp{} = rtp, ssrc), do: {:ok, %{rtp | ssrc: ssrc}}

  defp normalize_rtp(packet, ssrc) when is_binary(packet) do
    case Rtp.decode(packet) do
      {:ok, rtp} -> {:ok, %{rtp | ssrc: ssrc}}
      error -> error
    end
  end

  defp normalize_rtp(_, _), do: {:error, :invalid_packet}

  defp do_send_datachannel(%{sctp: assoc} = state, channel_ref, data, type)
       when not is_nil(assoc) and type in [:string, :binary] do
    t0 = System.monotonic_time(:microsecond)

    case SctpAssociation.send(assoc, channel_ref, data, type) do
      {events, assoc} ->
        Logger.debug(
          "xgw peer datachannel send bytes=#{byte_size(data)} ref=#{inspect(channel_ref)} type=#{type} ok"
        )

        state = Sctp.flush_events(%{state | sctp: assoc}, events, &send_dtls_app/2)

        if System.get_env("XYLON_DC_PROFILE") in ["1", "true", "yes"] and
             :erlang.phash2(t0, 200) == 0 do
          mb =
            case Process.info(self(), :message_queue_len) do
              {:message_queue_len, n} -> n
              _ -> -1
            end

          Logger.warning(
            "xgw dc profile send_us=#{System.monotonic_time(:microsecond) - t0} mb=#{mb} events=#{length(events)}"
          )
        end

        {:ok, state}

      {:error, reason, assoc} ->
        Logger.warning(
          "xgw peer datachannel send bytes=#{byte_size(data)} ref=#{inspect(channel_ref)} type=#{type} fail=#{inspect(reason)}"
        )

        emit_dc_send_error(state, channel_ref, reason)
        {{:error, reason}, %{state | sctp: assoc}}
    end
  end

  defp do_send_datachannel(state, channel_ref, data, type) do
    Logger.warning(
      "xgw peer datachannel send fail=:no_sctp ref=#{inspect(channel_ref)} bytes=#{byte_size(data)} type=#{type}"
    )

    emit_dc_send_error(state, channel_ref, :no_sctp)
    {{:error, :no_sctp}, state}
  end

  defp emit_dc_send_error(state, channel_ref, reason) do
    :telemetry.execute(
      [:xgw, :peer, :dc_send_error],
      %{count: 1},
      %{reason: reason, channel_ref: channel_ref}
    )

    handler = Map.get(state, :handler)

    if is_pid(handler) do
      send(handler, {:xgw, :datachannel_send_error, self(), channel_ref, reason})
    end

    :ok
  end

  defp do_open_datachannel(%{sctp: assoc} = state, label, opts) when not is_nil(assoc) do
    case SctpAssociation.open_channel(assoc, label, opts) do
      {events, channel_ref, assoc} ->
        state = Sctp.flush_events(%{state | sctp: assoc}, events, &send_dtls_app/2)
        info = channel_info(state.sctp, channel_ref, label)
        send(state.handler, {:xgw, :datachannel, self(), info})
        {{:ok, info}, state}

      {:error, reason, assoc} ->
        {{:error, reason}, %{state | sctp: assoc}}
    end
  end

  defp do_open_datachannel(state, _label, _opts) do
    {{:error, :not_connected}, state}
  end

  defp channel_info(%{channels: channels}, channel_ref, label) when is_map(channels) do
    case Map.get(channels, channel_ref) do
      %{id: id} = ch when is_integer(id) ->
        %{
          ref: channel_ref,
          label: Map.get(ch, :label, label),
          id: id,
          reliability: Map.get(ch, :reliability),
          order: if(Map.get(ch, :ordered, true), do: :ordered, else: :unordered),
          param: Map.get(ch, :param)
        }

      _ ->
        %{ref: channel_ref, label: label, id: -1}
    end
  end

  defp channel_info(_, channel_ref, label), do: %{ref: channel_ref, label: label, id: -1}

  defp do_send_rtp(%{phase: :media, selected_transport: :tcp, srtp: srtp} = state, ssrc, packet)
       when not is_nil(srtp) do
    with {:ok, rtp} <- normalize_rtp(packet, ssrc),
         {:ok, wire, srtp2} <- SRTPSession.encrypt(srtp, :rtp, rtp),
         :ok <- send_wire(state, wire) do
      {:ok, %{state | srtp: srtp2}}
    else
      {:error, %SRTPSession{} = srtp2} ->
        {{:error, :encrypt_failed}, %{state | srtp: srtp2}}

      {:error, reason} ->
        {{:error, reason}, state}

      _ ->
        {{:error, :invalid_packet}, state}
    end
  end

  defp do_send_rtp(%{phase: :media, srtp: srtp} = state, ssrc, packet) when not is_nil(srtp) do
    case SendHandle.send_rtp(self(), ssrc, packet) do
      :ok ->
        {:ok, state}

      {:error, :not_ready} ->
        state = publish_send_handle(state)

        case SendHandle.send_rtp(self(), ssrc, packet) do
          :ok -> {:ok, state}
          {:error, reason} -> {{:error, reason}, state}
        end

      {:error, :use_genserver} ->
        with {:ok, rtp} <- normalize_rtp(packet, ssrc),
             {:ok, wire, srtp2} <- SRTPSession.encrypt(srtp, :rtp, rtp),
             :ok <- send_wire(state, wire) do
          {:ok, %{state | srtp: srtp2}}
        else
          {:error, %SRTPSession{} = srtp2} ->
            {{:error, :encrypt_failed}, %{state | srtp: srtp2}}

          {:error, reason} ->
            {{:error, reason}, state}

          _ ->
            {{:error, :invalid_packet}, state}
        end

      {:error, reason} ->
        {{:error, reason}, state}
    end
  end

  defp do_send_rtp(state, _ssrc, _packet), do: {{:error, :not_connected}, state}

  defp publish_send_handle(state) do
    _ = SendHandle.publish_peer_state(self(), state)
    state
  end

  defp invalidate_send_handle(state) do
    _ = SendHandle.invalidate(self())
    state
  end

  defp normalize_rtcp(%Rtcp{encrypted: nil} = rtcp), do: {:ok, rtcp}
  defp normalize_rtcp(%Rtcp{}), do: {:error, :invalid_packet}

  defp normalize_rtcp(packet) when is_binary(packet) do
    case Rtcp.decode(packet) do
      {:ok, rtcp} -> normalize_rtcp(rtcp)
    end
  end

  defp normalize_rtcp(_), do: {:error, :invalid_packet}

  defp send_wire(%{ssl_sock: ssl_sock, selected_transport: :tcp}, wire) when not is_nil(ssl_sock) do
    :ssl.send(ssl_sock, wire)
  end

  defp send_wire(%{listener: listener, selected: peer} = state, wire)
       when is_pid(listener) and not is_nil(peer) do
    case Turn.relay_send_allocation(state) do
      nil ->
        {ip, port} = peer
        Listener.send_datagram(listener, ip, port, wire)

      alloc ->
        send_recv = fn w, {tip, tport} ->
          Listener.turn_request(listener, tip, tport, Listener.gather_timeout_ms(listener), w)
        end

        _ = Client.create_permission(send_recv, alloc, peer)

        if channel = Map.get(state.peer_channels, peer) do
          _ = Client.channel_bind(send_recv, alloc, peer, channel)
        end

        payload = Turn.encode_relay_app_data(state, alloc, peer, wire)

        Listener.send_datagram(
          listener,
          elem(alloc.turn_server, 0),
          elem(alloc.turn_server, 1),
          payload
        )
    end
  end

  defp send_wire(%{selected: nil}, _wire), do: {:error, :no_selected_pair}
  defp send_wire(%{listener: nil}, _wire), do: {:error, :no_selected_pair}
  defp send_wire(_state, _wire), do: {:error, :no_selected_pair}
end
