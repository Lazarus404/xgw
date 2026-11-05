defmodule XGW.Application do
  @moduledoc """
  OTP application entry for XGW.

  On boot this module:

  1. Loads the patched OTP DTLS packet demux (`XGW.DTLS.OtpDemux`) so DTLS can
     send on the shared Listener UDP socket instead of a private `:gen_udp`.
  2. Ensures the `XGW.Peer.SendHandle` and `XGW.Peer.Datachannel` ETS tables exist
     (RTP hot path and DC child lookup).
  3. Starts a `DynamicSupervisor` (`XGW.PeerSupervisor`) that owns `XGW.Peer`
     processes.

  Listeners are started by the host (your app, the browser spike, or tests),
  not here.

  ## RFCs

  Bootstraps OTP pieces used by the stack above (no wire-protocol role of its own).
  DTLS demux patch supports the RFC 7983 shared-socket model.
  """
  use Application

  @doc """
  Starts the XGW supervision tree.

  Always returns `{:ok, pid}` of the root supervisor when children start cleanly.
  """
  @impl true
  def start(_type, _args) do
    _ = XGW.DTLS.OtpDemux.patch!()
    _ = XGW.Peer.SendHandle.ensure_table!()
    _ = XGW.Peer.Datachannel.ensure_table!()

    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: XGW.PeerSupervisor}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: XGW.Supervisor)
  end
end
