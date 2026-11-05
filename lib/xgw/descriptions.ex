defmodule XGW.Descriptions do
  @moduledoc """
  Turns negotiated Session Description Protocol (SDP) text into a transport
  config map that `XGW.Peer` can use.

  ## What SDP is (for readers new to WebRTC)

  Before two endpoints send audio or video, they exchange short text documents
  called **SDP offers and answers**. Those documents list:

  - which codecs and media lines are in use
  - **ICE** usernames/passwords used to authenticate connectivity probes
  - the **DTLS** certificate fingerprint used to trust the encryption handshake
  - optional **candidates** (IP/port addresses to try)
  - whether a **data channel** (SCTP) is negotiated

  Signaling (HTTP, WebSocket, SIP) carries those documents. XGW does not invent
  SDP; it consumes the pair your app already negotiated (for example via
  WebSocket/JSEP or SIP + [xsdp](https://github.com/Lazarus404/xsdp)) and
  extracts only the fields needed to run ICE/DTLS/SRTP.

  ## Behavior notes

  Uses `XMediaLib.SDP` only. ICE-lite v1 picks the first bundled DTLS-SRTP
  m-line for fingerprint and ICE credentials. Session-level `a=fingerprint` /
  ICE / setup attributes (common in Firefox) are inherited onto media lines
  when those fields are absent at media level.

  ## RFCs

  * RFC 8866 -- Session Description Protocol (SDP)
  * RFC 8829 -- JSEP (offer/answer usage in WebRTC)
  * RFC 8445 -- ICE credentials and candidates in SDP
  * RFC 8122 -- `a=fingerprint`
  * RFC 8841 -- SDP for SCTP data channels (when an application m-line is present)
  """

  alias XMediaLib.SDP
  alias XMediaLib.SDP.{Fingerprint, Group, Media, Ssrc}

  @typedoc "SDP offer or answer as binary or parsed struct."
  @type sdp_input :: binary() | SDP.t()

  @typedoc """
  Parsed transport and media config for one peer.

  ## Fields

  * `:remote_fingerprint` / `:local_fingerprint` - DTLS cert digests from SDP
  * `:setup` - local DTLS setup (`:passive` / `:active` / ...)
  * `:bundle_mids` - BUNDLE group mids from the offer
  * `:media_by_mid` - per-mid codec/SSRC summary from the offer
  * `:remote_candidates` / `:local_candidates` - ICE candidates from offer/answer
  * `:ssrc_to_mid` - offer SSRC map used to tag inbound RTP meta
  * `:sctp` - negotiated data-channel ports, or `nil`
  * `:ice` - local/remote ufrag, pwd, and setup atoms
  """
  @type config :: %{
          remote_fingerprint: Fingerprint.t(),
          local_fingerprint: Fingerprint.t(),
          setup: Media.setup(),
          bundle_mids: [String.t()],
          media_by_mid: %{optional(String.t()) => media_info()},
          remote_candidates: [SDP.Candidate.t()],
          local_candidates: [SDP.Candidate.t()],
          ssrc_to_mid: %{optional(non_neg_integer()) => String.t()},
          sctp: sctp_info() | nil,
          ice: %{
            local_ufrag: String.t(),
            local_pwd: String.t(),
            remote_ufrag: String.t(),
            remote_pwd: String.t(),
            local_setup: Media.setup(),
            remote_setup: Media.setup()
          }
        }

  @typedoc """
  Negotiated SCTP data-channel ports when an application m-line is present.

  ## Fields

  * `:remote_port` / `:local_port` - SCTP port numbers from offer/answer
  * `:max_message_size` - optional max message size from SDP
  """
  @type sctp_info :: %{
          remote_port: non_neg_integer(),
          local_port: non_neg_integer(),
          max_message_size: non_neg_integer() | nil
        }

  @typedoc """
  Per-m-line media summary from the remote offer.

  ## Fields

  * `:mid` - media identification tag
  * `:type` / `:protocol` - SDP media type and proto
  * `:rtcp_mux` - whether RTCP shares the RTP port
  * `:codecs` / `:ssrcs` - negotiated codecs and SSRCs
  """
  @type media_info :: %{
          mid: String.t() | nil,
          type: Media.type() | nil,
          protocol: Media.protocol() | nil,
          rtcp_mux: boolean(),
          codecs: list(SDP.Codec.t()),
          ssrcs: list(Ssrc.t())
        }

  @doc """
  Parses offer and answer into peer config.

  Returns `{:error, :invalid_sdp}`, `{:error, :missing_fingerprint}`,
  `{:error, :missing_ice_credentials}`, or `{:error, :invalid_setup}` when
  `ice_lite: true` and local setup is not `:passive`.
  """
  @spec build(sdp_input(), sdp_input(), keyword()) :: {:ok, config()} | {:error, term()}
  def build(remote_offer, local_answer, opts \\ []) do
    ice_lite = Keyword.get(opts, :ice_lite, true)

    with {:ok, offer} <- parse_sdp(remote_offer),
         {:ok, answer} <- parse_sdp(local_answer),
         bundle_mids <- bundle_mids(offer),
         {:ok, offer_media} <- first_dtls_media(offer, bundle_mids),
         {:ok, answer_media} <- matching_media(answer, offer_media.mid, bundle_mids) do
      config = %{
        remote_fingerprint: offer_media.fingerprint,
        local_fingerprint: answer_media.fingerprint,
        setup: answer_media.setup,
        bundle_mids: bundle_mids,
        media_by_mid: media_map(offer, bundle_mids),
        remote_candidates: remote_candidates(offer, bundle_mids),
        local_candidates: local_candidates(answer, bundle_mids),
        ssrc_to_mid: ssrc_map(offer, bundle_mids),
        sctp: sctp_info(offer, answer, bundle_mids),
        ice: %{
          local_ufrag: answer_media.ice_ufrag,
          local_pwd: answer_media.ice_pwd,
          remote_ufrag: offer_media.ice_ufrag,
          remote_pwd: offer_media.ice_pwd,
          local_setup: answer_media.setup,
          remote_setup: offer_media.setup
        }
      }

      with :ok <- validate_ice(config.ice),
           :ok <- validate_fingerprints(config),
           :ok <- validate_setup(config.setup, ice_lite) do
        {:ok, config}
      end
    end
  end

  @doc """
  Parses a restart offer for new remote ICE credentials and candidates.

  Local ufrag/pwd are unchanged in v1; only remote side updates.
  """
  @spec restart_remote(sdp_input()) ::
          {:ok,
           %{
             remote_ice_ufrag: String.t(),
             remote_ice_pwd: String.t(),
             remote_candidates: [SDP.Candidate.t()]
           }}
          | {:error, term()}
  def restart_remote(offer) do
    with {:ok, sdp} <- parse_sdp(offer),
         bundle_mids <- bundle_mids(sdp),
         {:ok, media} <- first_dtls_media(sdp, bundle_mids) do
      {:ok,
       %{
         remote_ice_ufrag: media.ice_ufrag,
         remote_ice_pwd: media.ice_pwd,
         remote_candidates: remote_candidates(sdp, bundle_mids)
       }}
    end
  end

  @doc """
  Parses SDP input into `%XMediaLib.SDP{}`.

  Accepts a parsed struct or binary. Returns `{:error, :invalid_sdp}` for
  non-string, non-struct input.
  """
  @spec parse_sdp(sdp_input()) :: {:ok, SDP.t()} | {:error, :invalid_sdp}
  def parse_sdp(%SDP{} = sdp), do: {:ok, sdp}

  def parse_sdp(raw) when is_binary(raw) do
    case SDP.parse(raw) do
      {:ok, sdp} -> {:ok, sdp}
      {:error, _} -> {:error, :invalid_sdp}
    end
  end

  def parse_sdp(_), do: {:error, :invalid_sdp}

  @doc """
  Compares two SDP fingerprints (case-insensitive value).

  ## Examples

      iex> a = %XMediaLib.SDP.Fingerprint{algorithm: "sha-256", value: "aa:bb:cc"}
      iex> b = %XMediaLib.SDP.Fingerprint{algorithm: "SHA-256", value: "AA:BB:CC"}
      iex> XGW.Descriptions.fingerprints_match?(a, b)
      true

      iex> a = %XMediaLib.SDP.Fingerprint{algorithm: "sha-256", value: "aa:bb:cc"}
      iex> b = %XMediaLib.SDP.Fingerprint{algorithm: "sha-256", value: "dd:ee:ff"}
      iex> XGW.Descriptions.fingerprints_match?(a, b)
      false
  """
  @spec fingerprints_match?(Fingerprint.t(), Fingerprint.t()) :: boolean()
  def fingerprints_match?(%Fingerprint{algorithm: a1, value: v1}, %Fingerprint{algorithm: a2, value: v2}) do
    String.downcase(a1) == String.downcase(a2) and
      normalize_fingerprint(v1) == normalize_fingerprint(v2)
  end

  @doc """
  Normalizes an SDP fingerprint value to uppercase trimmed hex.

  ## Examples

      iex> XGW.Descriptions.normalize_fingerprint("aa:bb:cc")
      "AA:BB:CC"

      iex> XGW.Descriptions.normalize_fingerprint("  aa:bb  ")
      "AA:BB"
  """
  @spec normalize_fingerprint(String.t()) :: String.t()
  def normalize_fingerprint(value) do
    value |> String.upcase() |> String.trim()
  end

  defp bundle_mids(%SDP{groups: groups}) do
    case Enum.find(groups, &(&1.semantics == "BUNDLE")) do
      %Group{mids: mids} -> mids
      _ -> []
    end
  end

  defp first_dtls_media(%SDP{} = sdp, bundle_mids) do
    sdp.media
    |> Enum.filter(&dtls_media?/1)
    |> Enum.filter(fn m -> bundled?(m, bundle_mids) end)
    |> Enum.map(&with_session_defaults(&1, sdp))
    |> Enum.find_value(&valid_media/1)
    |> case do
      nil -> {:error, :missing_fingerprint}
      media -> {:ok, media}
    end
  end

  defp matching_media(%SDP{} = sdp, mid, bundle_mids) do
    sdp.media
    |> Enum.filter(&dtls_media?/1)
    |> Enum.filter(fn m -> bundled?(m, bundle_mids) end)
    |> Enum.find(fn m -> m.mid == mid end)
    |> case do
      nil -> first_dtls_media(%{sdp | groups: []}, bundle_mids)
      media -> valid_media(with_session_defaults(media, sdp))
    end
    |> case do
      nil -> {:error, :missing_fingerprint}
      media -> {:ok, media}
    end
  end

  # Firefox (and some peers) put fingerprint / ICE / setup at session level only.
  defp with_session_defaults(%Media{} = media, %SDP{attributes: attrs}) do
    media
    |> maybe_put_fingerprint(session_fingerprint(attrs))
    |> maybe_put_field(:ice_ufrag, session_string(attrs, "ice-ufrag"))
    |> maybe_put_field(:ice_pwd, session_string(attrs, "ice-pwd"))
    |> maybe_put_setup(session_setup(attrs))
  end

  defp maybe_put_fingerprint(%Media{fingerprint: nil} = m, %Fingerprint{} = fp),
    do: %{m | fingerprint: fp}

  defp maybe_put_fingerprint(m, _), do: m

  defp maybe_put_field(%Media{} = m, :ice_ufrag, u) when is_binary(u) do
    if is_nil(m.ice_ufrag), do: %{m | ice_ufrag: u}, else: m
  end

  defp maybe_put_field(%Media{} = m, :ice_pwd, p) when is_binary(p) do
    if is_nil(m.ice_pwd), do: %{m | ice_pwd: p}, else: m
  end

  defp maybe_put_field(m, _, _), do: m

  defp maybe_put_setup(%Media{setup: nil} = m, setup) when not is_nil(setup), do: %{m | setup: setup}
  defp maybe_put_setup(m, _), do: m

  defp session_fingerprint(attrs) do
    case session_string(attrs, "fingerprint") do
      nil ->
        nil

      value ->
        case String.split(value, " ", parts: 2) do
          [algo, fp] when fp != "" -> %Fingerprint{algorithm: algo, value: fp}
          _ -> nil
        end
    end
  end

  defp session_setup(attrs) do
    case session_string(attrs, "setup") do
      "active" -> :active
      "passive" -> :passive
      "actpass" -> :actpass
      "holdconn" -> :holdconn
      _ -> nil
    end
  end

  defp session_string(attrs, name) do
    Enum.find_value(attrs, fn
      {^name, v} when is_binary(v) and v != "" -> v
      _ -> nil
    end)
  end

  defp valid_media(%Media{fingerprint: %Fingerprint{} = fp} = m)
       when is_binary(m.ice_ufrag) and is_binary(m.ice_pwd) do
    if fp.value != "", do: m, else: nil
  end

  defp valid_media(_), do: nil

  defp dtls_media?(media), do: dtls_srtp?(media) or sctp_media?(media)

  defp dtls_srtp?(%Media{protocol: proto}) do
    proto in [:UDP_TLS_RTP_SAVPF, :RTP_SAVPF] or
      (is_binary(proto) and String.contains?(proto, "TLS") and String.contains?(proto, "RTP"))
  end

  defp sctp_media?(%Media{type: :application, protocol: :UDP_DTLS_SCTP}), do: true
  defp sctp_media?(%Media{protocol: :UDP_DTLS_SCTP}), do: true

  defp sctp_media?(%Media{protocol: proto}) when is_binary(proto) do
    String.contains?(proto, "SCTP")
  end

  defp sctp_media?(_), do: false

  defp sctp_info(offer, answer, bundle_mids) do
    with %Media{sctp_port: remote_port} = _om when is_integer(remote_port) <-
           find_sctp_media(offer, bundle_mids),
         %Media{sctp_port: local_port} = am when is_integer(local_port) <-
           find_sctp_media(answer, bundle_mids) do
      %{
        remote_port: remote_port,
        local_port: local_port,
        max_message_size: am.max_message_size
      }
    else
      _ -> nil
    end
  end

  defp find_sctp_media(%SDP{media: media}, bundle_mids) do
    media
    |> Enum.filter(&sctp_media?/1)
    |> Enum.filter(&bundled?(&1, bundle_mids))
    |> List.first()
  end

  defp bundled?(_media, []), do: true

  defp bundled?(%Media{mid: mid}, bundle_mids) when is_binary(mid) do
    mid in bundle_mids
  end

  defp bundled?(_, _), do: false

  defp media_map(%SDP{media: media}, bundle_mids) do
    media
    |> Enum.filter(&bundled?(&1, bundle_mids))
    |> Enum.filter(&(&1.mid))
    |> Map.new(fn m ->
      {m.mid,
       %{
         mid: m.mid,
         type: m.type,
         protocol: m.protocol,
         rtcp_mux: m.rtcp_mux,
         codecs: m.codecs,
         ssrcs: m.ssrcs
       }}
    end)
  end

  defp remote_candidates(%SDP{media: media}, bundle_mids) do
    media
    |> Enum.filter(&bundled?(&1, bundle_mids))
    |> Enum.flat_map(& &1.candidates)
  end

  defp local_candidates(%SDP{media: media}, bundle_mids) do
    media
    |> Enum.filter(&bundled?(&1, bundle_mids))
    |> Enum.flat_map(& &1.candidates)
  end

  defp ssrc_map(%SDP{media: media}, bundle_mids) do
    for m <- media,
        bundled?(m, bundle_mids),
        is_binary(m.mid),
        %Ssrc{id: ssrc} <- m.ssrcs,
        ssrc > 0,
        into: %{} do
      {ssrc, m.mid}
    end
  end

  defp validate_ice(%{local_ufrag: u, local_pwd: p, remote_ufrag: r})
       when is_binary(u) and u != "" and is_binary(p) and p != "" and is_binary(r) and r != "",
       do: :ok

  defp validate_ice(_), do: {:error, :missing_ice_credentials}

  defp validate_fingerprints(%{remote_fingerprint: rf, local_fingerprint: lf}) do
    if rf.algorithm != "" and lf.algorithm != "",
      do: :ok,
      else: {:error, :missing_fingerprint}
  end

  defp validate_setup(:passive, true), do: :ok
  defp validate_setup(_setup, true), do: {:error, :invalid_setup}
  defp validate_setup(_setup, false), do: :ok
end
