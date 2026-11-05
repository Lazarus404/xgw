defmodule XGW.Trunk.PipeRtpTest do
  use ExUnit.Case, async: false

  alias XGW.Trunk.Pipe
  alias XMediaLib.Rtp

  @master_key <<0xE1F97A0D3E018BE0D64FA32C06DE4139::size(128)>>
  @master_salt <<0x0EC675AD498AFEEBB6960B3AABE6::size(112)>>
  @ssrc 42
  @payload <<"trunk-rtp-lab">>

  @rtp %Rtp{
    padding: 0,
    marker: 0,
    payload_type: 111,
    sequence_number: 1,
    timestamp: 1000,
    ssrc: @ssrc,
    csrcs: [],
    extension: nil,
    payload: @payload
  }

  test "two pipes exchange one RTP packet over UDP with SRTP" do
    handler_a = self()
    handler_b = self()

    assert {:ok, pipe_a} =
             Pipe.start_link(
               handler: handler_a,
               master_key: @master_key,
               master_salt: @master_salt
             )

    assert {:ok, pipe_b} =
             Pipe.start_link(
               handler: handler_b,
               master_key: @master_key,
               master_salt: @master_salt
             )

    assert {:ok, {ip_a, port_a}} = Pipe.local_addr(pipe_a)
    assert {:ok, {ip_b, port_b}} = Pipe.local_addr(pipe_b)

    assert :ok = Pipe.connect(pipe_a, ip_b, port_b)
    assert :ok = Pipe.connect(pipe_b, ip_a, port_a)

    before_a = Pipe.stats(pipe_a)
    before_b = Pipe.stats(pipe_b)

    assert :ok = Pipe.send_rtp(pipe_a, @ssrc, @rtp)

    assert_receive {Pipe, :rtp, ^pipe_b, @ssrc, %Rtp{payload: @payload, ssrc: @ssrc}}, 2000

    after_a = Pipe.stats(pipe_a)
    after_b = Pipe.stats(pipe_b)

    assert after_a.udp_out > before_a.udp_out
    assert after_b.udp_in > before_b.udp_in
  end
end
