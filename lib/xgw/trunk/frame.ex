defmodule XGW.Trunk.Frame do
  @moduledoc """
  Multiplex header for inter-edge trunk UDP payloads.

  ## What problem this solves

  One trunk pipe carries RTP, RTCP, and opaque datachannel bytes. A single
  leading type byte keeps demux cheap without WebRTC/ICE on the SFU-to-SFU path.

  ## RFCs

  None directly; RTP/SRTP payloads inside follow RFC 3550 / RFC 3711.
  """

  @type kind :: :rtp | :rtcp | :dc

  @rtp 1
  @rtcp 2
  @dc 3

  @doc """
  Encodes `kind` and `payload` as `<<type, payload::binary>>`.
  """
  @spec encode(kind(), binary()) :: binary()
  def encode(:rtp, payload) when is_binary(payload), do: <<@rtp, payload::binary>>
  def encode(:rtcp, payload) when is_binary(payload), do: <<@rtcp, payload::binary>>
  def encode(:dc, payload) when is_binary(payload), do: <<@dc, payload::binary>>

  @doc """
  Decodes a multiplex frame. Returns `{:ok, kind, payload}` or `{:error, :bad_frame}`.
  """
  @spec decode(binary()) :: {:ok, kind(), binary()} | {:error, :bad_frame}
  def decode(<<@rtp, payload::binary>>) when byte_size(payload) > 0, do: {:ok, :rtp, payload}
  def decode(<<@rtcp, payload::binary>>) when byte_size(payload) > 0, do: {:ok, :rtcp, payload}
  def decode(<<@dc, payload::binary>>) when byte_size(payload) > 0, do: {:ok, :dc, payload}
  def decode(_), do: {:error, :bad_frame}

  @doc """
  Packs an opaque datachannel frame body: `<<label_len::16, label::binary, data::binary>>`.
  """
  @spec encode_dc(binary(), binary()) :: binary()
  def encode_dc(label, data) when is_binary(label) and is_binary(data) do
    <<byte_size(label)::16, label::binary, data::binary>>
  end

  @doc """
  Unpacks a datachannel frame body.
  """
  @spec decode_dc(binary()) :: {:ok, binary(), binary()} | {:error, :bad_dc}
  def decode_dc(<<label_len::16, rest::binary>>) when label_len >= 0 do
    case rest do
      <<label::binary-size(^label_len), data::binary>> ->
        {:ok, label, data}

      _ ->
        {:error, :bad_dc}
    end
  end

  def decode_dc(_), do: {:error, :bad_dc}
end
