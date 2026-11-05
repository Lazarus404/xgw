defmodule XGW.DTLS.OtpDemux do
  @moduledoc """
  Patches Erlang/OTP's DTLS packet demux so XGW can share one UDP socket.

  ## Why a patch is needed

  Stock OTP DTLS assumes each connection owns a private `:gen_udp` socket.
  XGW deliberately multiplexes STUN, DTLS, and SRTP on **one** Listener socket
  (standard WebRTC demux). Outbound DTLS must therefore call
  `XGW.DTLS.Transport` instead of `:gen_udp.send/4`.

  At application start, `patch!/0` loads a drop-in `dtls_packet_demux` BEAM from
  XGW's `ebin` when present. If the file is missing, startup continues with
  stock OTP (suitable for environments that do not run shared-socket DTLS).

  ## RFCs

  * RFC 7983 -- WebRTC demux model that motivates a shared UDP socket
  * RFC 9147 / RFC 6347 -- DTLS (OTP connection that must send on that socket)
  """

  @doc """
  Reloads `ebin/dtls_packet_demux.beam` when present.

  Always returns `:ok`. Load failures are logged and ignored so the host app
  can still boot (for example in test without the patched BEAM).
  """
  @spec patch!() :: :ok
  def patch! do
    beam =
      :xgw
      |> :code.lib_dir()
      |> Path.join("ebin/dtls_packet_demux.beam")

    if File.exists?(beam) do
      _ = :code.purge(:dtls_packet_demux)
      abs = beam |> Path.rootname() |> String.to_charlist()

      case :code.load_abs(abs) do
        {:module, :dtls_packet_demux} ->
          :ok

        {:error, reason} ->
          require Logger
          Logger.warning("xgw DTLS otp demux patch load failed: #{inspect(reason)}")
          :ok
      end
    else
      :ok
    end
  end
end
