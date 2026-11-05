defmodule XGW.Spike.SDP do
  @moduledoc """
  Minimal SDP answer builder and helpers for the browser spike (`mix xgw.spike`).
  """

  @doc """
  Builds a minimal WebRTC answer from an offer and local ICE/DTLS parameters.

  Opts may include `:codec` as `:opus | :pcmu | :pcma | :g722` (default `:opus`).
  The answer lists only that codec so the browser is forced onto it.

  When the offer includes an SCTP application m-line, the answer BUNDLEs a matching
  `m=application` with `a=sctp-port` / `a=max-message-size`.
  """
  @spec answer(binary(), keyword()) :: binary()
  def answer(offer, opts) when is_binary(offer) and is_list(opts) do
    ufrag = Keyword.fetch!(opts, :ice_ufrag)
    pwd = Keyword.fetch!(opts, :ice_pwd)
    fingerprint = Keyword.fetch!(opts, :fingerprint)
    port = Keyword.fetch!(opts, :port)
    codec = normalize_codec(Keyword.get(opts, :codec, :opus))
    {pt, rtpmap, fmtp} = codec_lines(offer, codec)
    mid = mid_from_offer(offer)
    sctp = sctp_from_offer(offer)
    fallback_ip = Keyword.fetch!(opts, :ip)

    candidate_lines =
      case Keyword.get(opts, :candidate_lines) do
        lines when is_list(lines) and lines != [] ->
          Enum.map(lines, fn line ->
            if String.starts_with?(line, "candidate:"), do: line, else: "candidate:" <> line
          end)

        _ ->
          ips = Keyword.get(opts, :ips, [fallback_ip])

          ips
          |> Enum.with_index(1)
          |> Enum.map(fn {addr, idx} ->
            "a=candidate:#{idx} 1 udp 2130706431 #{format_ip(addr)} #{port} typ host"
          end)
      end

    default_ip =
      opts
      |> Keyword.get(:ips, [fallback_ip])
      |> default_answer_ip(fallback_ip)

    candidate_attrs =
      Enum.map(candidate_lines, fn line ->
        String.replace_prefix(line, "a=", "")
      end)

    {media_ip, media_port} = media_endpoint(candidate_attrs, default_ip, port)
    ip_str = format_ip(media_ip)
    audio = audio_section(offer)

    codec_attrs =
      ["a=rtpmap:#{pt} #{rtpmap}"] ++
        if(fmtp, do: ["a=fmtp:#{pt} #{fmtp}"], else: [])

    bundle_mids =
      case sctp do
        %{mid: sctp_mid} -> "#{mid} #{sctp_mid}"
        nil -> mid
      end

    common_ice = [
      "a=ice-ufrag:#{ufrag}",
      "a=ice-pwd:#{pwd}",
      "a=fingerprint:sha-256 #{fingerprint}"
    ]

    audio_lines =
      [
        "m=audio #{media_port} UDP/TLS/RTP/SAVPF #{pt}",
        "c=IN IP4 #{ip_str}",
        "a=rtcp-mux"
      ] ++
        rtcp_rsize_lines(audio) ++
        [
          "a=setup:passive",
          "a=mid:#{mid}",
          "a=recvonly"
        ] ++
        extmap_lines(audio) ++
        common_ice ++
        codec_attrs ++
        Enum.map(candidate_attrs, &("a=" <> &1))

    sctp_lines =
      case sctp do
        %{mid: sctp_mid, port: sctp_port, max_message_size: max_msg} ->
          [
            "m=application #{media_port} UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 #{ip_str}",
            "a=setup:passive",
            "a=mid:#{sctp_mid}",
            "a=sctp-port:#{sctp_port}",
            "a=max-message-size:#{max_msg}"
          ] ++ common_ice ++ Enum.map(candidate_attrs, &("a=" <> &1))

        nil ->
          []
      end

    lines =
      [
        "v=0",
        "o=- 0 0 IN IP4 #{ip_str}",
        "s=-",
        "t=0 0",
        "a=group:BUNDLE #{bundle_mids}",
        "a=msid-semantic: WMS *"
      ] ++
        ice_options_lines(offer) ++
        audio_lines ++
        sctp_lines

    Enum.join(lines, "\r\n") <> "\r\n"
  end

  @doc """
  Host candidate IPs for the spike answer: loopback plus non-loopback IPv4 locals.
  """
  @spec detect_advert_ips() :: [:inet.ip_address()]
  def detect_advert_ips do
    lan =
      case :inet.getifaddrs() do
        {:ok, ifs} ->
          ifs
          |> Enum.reject(fn {name, _} ->
            name |> to_string() |> String.starts_with?("lo")
          end)
          |> Enum.flat_map(fn {_name, opts} ->
            for {:addr, {a, b, c, d}} when a != 127 <- opts, do: {a, b, c, d}
          end)

        _ ->
          []
      end

    [{127, 0, 0, 1} | lan]
    |> Enum.uniq()
  end

  @doc """
  Parses the browser's ICE ufrag and pwd from an offer SDP.

  Uses the last match so media-level credentials win over session-level duplicates.
  """
  @spec parse_ice(binary()) :: {String.t() | nil, String.t() | nil}
  def parse_ice(offer) when is_binary(offer) do
    ufrag = Regex.scan(~r/a=ice-ufrag:(\S+)/, offer) |> List.last() |> ice_value()
    pwd = Regex.scan(~r/a=ice-pwd:(\S+)/, offer) |> List.last() |> ice_value()
    {ufrag, pwd}
  end

  @doc """
  Coerces a codec atom or header string to `:opus | :pcmu | :pcma | :g722`.
  """
  @spec normalize_codec(term()) :: :opus | :pcmu | :pcma | :g722
  def normalize_codec(codec) when codec in [:opus, :pcmu, :pcma, :g722], do: codec

  def normalize_codec(codec) when is_binary(codec) do
    case String.downcase(codec) do
      "pcmu" -> :pcmu
      "pcma" -> :pcma
      "g722" -> :g722
      _ -> :opus
    end
  end

  def normalize_codec(_), do: :opus

  defp ice_value([_, value]), do: value
  defp ice_value(_), do: nil

  defp codec_lines(offer, :opus) do
    pt = rtpmap_pt(offer, ~r/a=rtpmap:(\d+) opus\/48000/i) || "111"
    {pt, "opus/48000/2", "minptime=10;useinbandfec=1"}
  end

  defp codec_lines(offer, :pcmu) do
    pt = rtpmap_pt(offer, ~r/a=rtpmap:(\d+) (?:PCMU|pcmu)\/8000/i) || "0"
    {pt, "PCMU/8000", nil}
  end

  defp codec_lines(offer, :pcma) do
    pt = rtpmap_pt(offer, ~r/a=rtpmap:(\d+) (?:PCMA|pcma)\/8000/i) || "8"
    {pt, "PCMA/8000", nil}
  end

  defp codec_lines(offer, :g722) do
    pt = rtpmap_pt(offer, ~r/a=rtpmap:(\d+) (?:G722|g722)\/8000/i) || "9"
    {pt, "G722/8000", nil}
  end

  defp rtpmap_pt(offer, regex) do
    case Regex.run(regex, offer) do
      [_, pt] -> pt
      _ -> nil
    end
  end

  defp mid_from_offer(offer) do
    case Regex.run(~r/a=mid:(\S+)/, offer) do
      [_, mid] -> mid
      _ -> "0"
    end
  end

  # When answer candidates include typ relay (relay-only), put that address on m=/c=
  # so DTLS/RTP target the relayed address instead of the listener host port.
  defp media_endpoint(candidate_attrs, fallback_ip, fallback_port) do
    relay =
      Enum.find_value(candidate_attrs, fn line ->
        case Regex.run(~r/ (\d{1,3}(?:\.\d{1,3}){3}) (\d+) typ relay\b/, line) do
          [_, ip_str, port_str] ->
            case :inet.parse_address(String.to_charlist(ip_str)) do
              {:ok, ip} -> {ip, String.to_integer(port_str)}
              _ -> nil
            end

          _ ->
            nil
        end
      end)

    relay || {fallback_ip, fallback_port}
  end

  defp sctp_from_offer(offer) do
    case Regex.run(~r/m=application[^\r\n]*UDP\/DTLS\/SCTP[^\r\n]*/i, offer) do
      nil ->
        nil

      _ ->
        mid =
          case Regex.run(~r/m=application[\s\S]*?a=mid:(\S+)/m, offer) do
            [_, m] -> m
            _ -> "1"
          end

        port =
          case Regex.run(~r/a=sctp-port:(\d+)/, offer) do
            [_, p] -> String.to_integer(p)
            _ -> 5000
          end

        max_msg =
          case Regex.run(~r/a=max-message-size:(\d+)/, offer) do
            [_, p] -> String.to_integer(p)
            _ -> 262_144
          end

        %{mid: mid, port: port, max_message_size: max_msg}
    end
  end

  defp audio_section(offer) do
    case Regex.run(~r/(m=audio[\s\S]*?)(?=^m=|\z)/m, offer) do
      [_, section] -> section
      _ -> offer
    end
  end

  defp ice_options_lines(offer) do
    if offer =~ ~r/^a=ice-options:.*\btrickle\b/m, do: ["a=ice-options:trickle"], else: []
  end

  defp rtcp_rsize_lines(audio) do
    if audio =~ ~r/^a=rtcp-rsize\b/m, do: ["a=rtcp-rsize"], else: []
  end

  defp extmap_lines(audio) do
    Regex.scan(~r/^a=extmap:\S+[^\r\n]*/m, audio)
    |> Enum.map(&hd/1)
  end

  defp default_answer_ip(ips, fallback) when is_list(ips) do
    Enum.find(ips, fallback, &non_loopback_ipv4?/1)
  end

  defp non_loopback_ipv4?({127, _, _, _}), do: false
  defp non_loopback_ipv4?({_, _, _, _}), do: true
  defp non_loopback_ipv4?(_), do: false

  defp format_ip(ip) when is_tuple(ip) do
    ip |> :inet.ntoa() |> to_string()
  end
end
