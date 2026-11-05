defmodule XGW.Test.SDPFixtures do
  @moduledoc false

  alias XMediaLib.SDP
  alias XMediaLib.SDP.{Codec, Fingerprint, Group, Media, Ssrc}

  @chrome_fingerprint "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"

  @doc false
  def chrome_offer, do: File.read!(Path.expand("../fixtures/sdp/chrome.sdp", __DIR__))

  @doc false
  def chrome_fingerprint, do: @chrome_fingerprint

  @doc false
  def xgw_answer(local_fingerprint, opts \\ []) do
    ufrag = Keyword.get(opts, :ufrag, "xgwufrag")
    pwd = Keyword.get(opts, :pwd, "xgwpasswordxgwpasswordx")
    port = Keyword.get(opts, :port, 9)
    host_line = Keyword.get(opts, :host_candidate)

    fp = %Fingerprint{algorithm: "sha-256", value: local_fingerprint}

    candidates =
      if host_line do
        [parse_candidate_line(host_line)]
      else
        []
      end

    audio = %Media{
      type: :audio,
      port: port,
      protocol: :UDP_TLS_RTP_SAVPF,
      formats: ["111"],
      ice_ufrag: ufrag,
      ice_pwd: pwd,
      fingerprint: fp,
      setup: :passive,
      mid: "0",
      direction: :recvonly,
      rtcp_mux: true,
      candidates: candidates,
      codecs: [%Codec{payload_type: 111, name: "opus", clock_rate: 48_000, encoding_params: "2"}]
    }

    %SDP{
      version: 0,
      session_name: "-",
      time: [%XMediaLib.SDP.Time{}],
      groups: [%Group{semantics: "BUNDLE", mids: ["0"]}],
      attributes: [{"ice-lite", true}],
      media: [audio]
    }
    |> encode!()
  end

  @doc false
  def xgw_full_answer(local_fingerprint, opts \\ []) do
    ufrag = Keyword.get(opts, :ufrag, "xgwufrag")
    pwd = Keyword.get(opts, :pwd, "xgwpasswordxgwpasswordx")
    port = Keyword.get(opts, :port, 9)
    host_line = Keyword.get(opts, :host_candidate)

    fp = %Fingerprint{algorithm: "sha-256", value: local_fingerprint}

    candidates =
      cond do
        lines = Keyword.get(opts, :candidate_lines) ->
          Enum.map(lines, &parse_candidate_line/1)

        host_line ->
          [parse_candidate_line(host_line)]

        true ->
          []
      end

    audio = %Media{
      type: :audio,
      port: port,
      protocol: :UDP_TLS_RTP_SAVPF,
      formats: ["111"],
      ice_ufrag: ufrag,
      ice_pwd: pwd,
      fingerprint: fp,
      setup: :passive,
      mid: "0",
      direction: :recvonly,
      rtcp_mux: true,
      candidates: candidates,
      codecs: [%Codec{payload_type: 111, name: "opus", clock_rate: 48_000, encoding_params: "2"}]
    }

    %SDP{
      version: 0,
      session_name: "-",
      time: [%XMediaLib.SDP.Time{}],
      groups: [%Group{semantics: "BUNDLE", mids: ["0"]}],
      media: [audio]
    }
    |> encode!()
  end

  @doc false
  def minimal_offer(ufrag, pwd, opts \\ []) do
    fp = Keyword.get(opts, :fingerprint, @chrome_fingerprint)
    ssrc = Keyword.get(opts, :ssrc, 1001)

    """
    v=0
    o=- 0 0 IN IP4 127.0.0.1
    s=-
    t=0 0
    a=group:BUNDLE 0
    m=audio 9 UDP/TLS/RTP/SAVPF 111
    c=IN IP4 0.0.0.0
    a=ice-ufrag:#{ufrag}
    a=ice-pwd:#{pwd}
    a=fingerprint:sha-256 #{fp}
    a=setup:actpass
    a=mid:0
    a=rtcp-mux
    a=rtpmap:111 opus/48000/2
    a=ssrc:#{ssrc} cname:test-audio
    """
  end

  @doc false
  def apply_with_listener(peer, listener, client_ufrag, client_pwd, server_ufrag, server_pwd) do
    fp = XGW.Listener.local_fingerprint(listener)

    XGW.Peer.apply_descriptions(
      peer,
      minimal_offer(client_ufrag, client_pwd),
      xgw_answer(fp, ufrag: server_ufrag, pwd: server_pwd)
    )
  end

  @doc false
  def xgw_answer_with_ssrc(local_fingerprint, ssrc \\ 1001) do
    ufrag = "xgwufrag"
    pwd = "xgwpasswordxgwpasswordx"
    fp = %Fingerprint{algorithm: "sha-256", value: local_fingerprint}

    audio = %Media{
      type: :audio,
      port: 9,
      protocol: :UDP_TLS_RTP_SAVPF,
      formats: ["111"],
      ice_ufrag: ufrag,
      ice_pwd: pwd,
      fingerprint: fp,
      setup: :passive,
      mid: "0",
      rtcp_mux: true,
      codecs: [%Codec{payload_type: 111, name: "opus", clock_rate: 48_000, encoding_params: "2"}],
      ssrcs: [%Ssrc{id: ssrc, attribute: "cname", value: "xgw-audio"}]
    }

    %SDP{
      version: 0,
      session_name: "-",
      time: [%XMediaLib.SDP.Time{}],
      groups: [%Group{semantics: "BUNDLE", mids: ["0"]}],
      attributes: [{"ice-lite", true}],
      media: [audio]
    }
    |> encode!()
  end

  defp encode!(sdp) do
    {:ok, bin} = SDP.encode(sdp)
    bin
  end

  defp parse_candidate_line(line) do
    line
    |> String.replace_prefix("candidate:", "")
    |> XMediaLib.SDP.Parser.Helpers.parse_candidate()
  end
end
