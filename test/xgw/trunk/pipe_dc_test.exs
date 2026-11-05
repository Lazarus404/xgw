defmodule XGW.Trunk.PipeDcTest do
  use ExUnit.Case, async: false

  alias XGW.Peer.SendHandle
  alias XGW.Trunk.Pipe
  alias XMediaLib.Rtp

  @master_key <<0xE1F97A0D3E018BE0D64FA32C06DE4139::size(128)>>
  @master_salt <<0x0EC675AD498AFEEBB6960B3AABE6::size(112)>>

  @rtp %Rtp{
    padding: 0,
    marker: 0,
    payload_type: 111,
    sequence_number: 2,
    timestamp: 2000,
    ssrc: 7,
    csrcs: [],
    extension: nil,
    payload: <<"via-handle">>
  }

  setup do
    SendHandle.ensure_table!()

    assert {:ok, pipe_a} =
             Pipe.start_link(
               handler: self(),
               master_key: @master_key,
               master_salt: @master_salt
             )

    assert {:ok, pipe_b} =
             Pipe.start_link(
               handler: self(),
               master_key: @master_key,
               master_salt: @master_salt
             )

    assert {:ok, {ip_a, port_a}} = Pipe.local_addr(pipe_a)
    assert {:ok, {ip_b, port_b}} = Pipe.local_addr(pipe_b)
    assert :ok = Pipe.connect(pipe_a, ip_b, port_b)
    assert :ok = Pipe.connect(pipe_b, ip_a, port_a)

    assert :ok = Pipe.publish_send_handles(pipe_a)
    assert :ok = Pipe.publish_send_handles(pipe_b)

    on_exit(fn ->
      SendHandle.invalidate(pipe_a)
      SendHandle.invalidate(pipe_b)
    end)

    %{pipe_a: pipe_a, pipe_b: pipe_b}
  end

  test "SendHandle.send_rtp reaches peer pipe over UDP", %{pipe_a: pipe_a, pipe_b: pipe_b} do
    assert :ok = SendHandle.send_rtp(pipe_a, 7, @rtp)
    assert_receive {Pipe, :rtp, ^pipe_b, 7, %Rtp{payload: <<"via-handle">>}}, 2000
  end

  test "SendHandle.send_datachannel reaches peer pipe over UDP", %{
    pipe_a: pipe_a,
    pipe_b: pipe_b
  } do
    assert {:ok, ref} = Pipe.ensure_label(pipe_a, "chat")
    assert :ok = SendHandle.send_datachannel(pipe_a, ref, "hello-trunk")
    assert_receive {Pipe, :dc, ^pipe_b, "chat", "hello-trunk"}, 2000
  end
end
