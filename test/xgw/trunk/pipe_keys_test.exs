defmodule XGW.Trunk.PipeKeysTest do
  use ExUnit.Case, async: false

  alias XGW.Trunk.{Crypto, Pipe}
  alias XMediaLib.Rtp

  @key_ab <<0xE1F97A0D3E018BE0D64FA32C06DE4139::size(128)>>
  @salt_ab <<0x0EC675AD498AFEEBB6960B3AABE6::size(112)>>
  @key_ba <<0xA1B2C3D4E5F60718293A4B5C6D7E8F90::size(128)>>
  @salt_ba <<0x112233445566778899AABBCCDDEE::size(112)>>
  @wrong_key <<0x000102030405060708090A0B0C0D0E0F::size(128)>>
  @wrong_salt <<0x101112131415161718191A1B1C1D::size(112)>>

  @rtp %Rtp{
    padding: 0,
    marker: 0,
    payload_type: 111,
    sequence_number: 1,
    timestamp: 1000,
    ssrc: 42,
    csrcs: [],
    extension: nil,
    payload: <<"dir-keys">>
  }

  test "directional Crypto: A write decrypts on B; wrong remote write fails" do
    a = Crypto.new(@key_ab, @salt_ab, @key_ba, @salt_ba)
    b = Crypto.new(@key_ba, @salt_ba, @key_ab, @salt_ab)
    wrong = Crypto.new(@key_ba, @salt_ba, @wrong_key, @wrong_salt)

    assert {:ok, wire, _} = Crypto.protect_rtp(a, @rtp)
    assert {:ok, %Rtp{payload: <<"dir-keys">>}, _} = Crypto.unprotect_rtp(b, wire)
    assert {:error, _} = Crypto.unprotect_rtp(wrong, wire)
  end

  test "two pipes with swapped write keys exchange RTP over UDP" do
    assert {:ok, pipe_a} =
             Pipe.start_link(
               handler: self(),
               local_write_key: @key_ab,
               local_write_salt: @salt_ab,
               remote_write_key: @key_ba,
               remote_write_salt: @salt_ba
             )

    assert {:ok, pipe_b} =
             Pipe.start_link(
               handler: self(),
               local_write_key: @key_ba,
               local_write_salt: @salt_ba,
               remote_write_key: @key_ab,
               remote_write_salt: @salt_ab
             )

    assert {:ok, {ip_a, port_a}} = Pipe.local_addr(pipe_a)
    assert {:ok, {ip_b, port_b}} = Pipe.local_addr(pipe_b)
    assert :ok = Pipe.connect(pipe_a, ip_b, port_b)
    assert :ok = Pipe.connect(pipe_b, ip_a, port_a)

    assert :ok = Pipe.send_rtp(pipe_a, 42, @rtp)
    assert_receive {Pipe, :rtp, ^pipe_b, 42, %Rtp{payload: <<"dir-keys">>}}, 2000
  end
end
