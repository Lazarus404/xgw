defmodule XGW.Peer.Sctp do
  @moduledoc """
  Starts and drives the SCTP association used for WebRTC data channels.

  ## What problem this solves

  Browsers open **data channels** for arbitrary binary/text beside audio/video.
  Under the hood that is **SCTP** inside the DTLS tunnel. This module starts a
  passive association when SDP negotiated SCTP and SSL is up, then applies
  association events (transmit, channel open/close, messages) into Peer or
  `XGW.Peer.Datachannel` state and handler callbacks.

  Production ownership of the live association and DTLS app-data socket is the
  per-Peer `XGW.Peer.Datachannel` process. Handler messages always carry the
  Peer pid as `peer_ref` (via state `:peer` when set).

  ## RFCs

  * RFC 8261 -- SCTP over DTLS
  * RFC 8831 -- WebRTC data channels
  * RFC 8841 -- SDP negotiation of SCTP
  """

  require Logger

  alias XSockets.Sctp.Association, as: SctpAssociation

  @doc """
  Starts a passive SCTP association when SDP negotiated SCTP and SSL is up.

  No-ops when SCTP was not negotiated, SSL is not ready, or `ex_sctp` is unloaded.
  """
  @spec maybe_start(map()) :: map()
  def maybe_start(%{config: %{sctp: sctp}, ssl_sock: sock} = state)
      when not is_nil(sctp) and not is_nil(sock) do
    if SctpAssociation.available?() do
      # Spike/XGW answers with setup:passive => DTLS server => SCTP passive (odd local ids).
      # Chrome (offerer / DTLS client) initiates the SCTP association.
      assoc = SctpAssociation.new(role: :passive)
      _ = :ssl.setopts(sock, mode: :binary, active: :once)

      Logger.info(
        "xgw peer SCTP association ready (passive, ports local=#{sctp.local_port} remote=#{sctp.remote_port})"
      )

      %{state | sctp: assoc}
    else
      Logger.warning("xgw peer SCTP negotiated but ex_sctp is not loaded")
      state
    end
  end

  def maybe_start(state), do: state

  @doc """
  Applies SCTP association events; `send_dtls` posts app data on the DTLS socket.

  Events include outbound SCTP chunks to transmit, channel lifecycle, and
  application messages that become `{:xgw, :datachannel_*, ...}` callbacks.
  """
  @spec flush_events(map(), list(), (map(), binary() -> :ok | {:error, term()})) :: map()
  def flush_events(state, events, send_dtls) when is_function(send_dtls, 2) do
    Enum.reduce(events, state, fn event, st -> handle_event(event, st, send_dtls) end)
  end

  defp handle_event({:transmit, packets}, state, send_dtls) do
    Enum.reduce(packets, state, fn pkt, st ->
      case send_dtls.(st, pkt) do
        :ok ->
          st

        {:error, reason} ->
          Logger.warning("xgw SCTP transmit failed: #{inspect(reason)}")
          st
      end
    end)
  end

  defp handle_event(:connected, state, _send_dtls) do
    Logger.info("xgw peer SCTP connected")
    send(state.handler, {:xgw, :sctp_connected, peer_ref(state)})
    state
  end

  defp handle_event({:channel_open, ref, label, id, meta}, state, _send_dtls) when is_map(meta) do
    Logger.info("xgw peer datachannel open label=#{inspect(label)} id=#{id}")

    info =
      %{ref: ref, label: label, id: id}
      |> Map.merge(Map.take(meta, [:reliability, :order, :param]))

    send(state.handler, {:xgw, :datachannel, peer_ref(state), info})
    state
  end

  # Compat for older association builds without transport meta.
  defp handle_event({:channel_open, ref, label, id}, state, send_dtls) do
    handle_event({:channel_open, ref, label, id, %{}}, state, send_dtls)
  end

  defp handle_event({:message, ref, data}, state, _send_dtls) do
    Logger.debug("xgw peer datachannel message bytes=#{byte_size(data)} ref=#{inspect(ref)}")
    send(state.handler, {:xgw, :datachannel_message, peer_ref(state), ref, data})
    state
  end

  defp handle_event({:channel_closed, ref}, state, _send_dtls) do
    send(state.handler, {:xgw, :datachannel_closed, peer_ref(state), ref})
    state
  end

  defp handle_event(:disconnected, state, _send_dtls) do
    send(state.handler, {:xgw, :sctp_disconnected, peer_ref(state)})
    %{state | sctp: nil}
  end

  defp handle_event({:timeout, _}, state, _send_dtls), do: state
  defp handle_event(_, state, _send_dtls), do: state

  # Datachannel child sets `:peer` to the owning Peer pid; Peer itself uses self().
  defp peer_ref(%{peer: peer}) when is_pid(peer), do: peer
  defp peer_ref(_state), do: self()
end
