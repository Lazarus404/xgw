defmodule XGW.ICE.BindingTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias XGW.ICE.Binding
  alias XMediaLib.Stun

  @creds %{
    ice_ufrag: "svr",
    ice_pwd: "serverpasswordpassword",
    remote_ice_ufrag: "cli",
    remote_ice_pwd: "clientpasswordpassword",
    tiebreaker: <<1, 2, 3, 4, 5, 6, 7, 8>>,
    role: :controlled
  }

  test "decode prefers local pwd for inbound checks without MI miss log" do
    # Browser connectivity checks are signed with the server (local) ice-pwd.
    browser = %{
      ice_ufrag: "cli",
      ice_pwd: "clientpasswordpassword",
      remote_ice_ufrag: "svr",
      remote_ice_pwd: "serverpasswordpassword",
      tiebreaker: <<1, 2, 3, 4, 5, 6, 7, 8>>,
      role: :controlling
    }

    wire = Binding.build_check_request(browser, 12345, transactionid: 42)

    log =
      capture_log(fn ->
        assert {:ok, %Stun{class: :request, method: :binding}} = Binding.decode(wire, @creds)
      end)

    refute log =~ "MESSAGE-INTEGRITY false"
  end

  test "decode still accepts peer-signed packets via remote pwd fallback" do
    # Outbound consent / full-ICE packets signed with the remote ice-pwd.
    wire = Binding.build_check_request(@creds, 12345, transactionid: 43)
    assert {:ok, %Stun{class: :request, method: :binding}} = Binding.decode(wire, @creds)
  end

  test "build_check_request includes username priority and role attr" do
    wire = Binding.build_check_request(@creds, 12345, transactionid: 99)
    assert {:ok, %Stun{class: :request, method: :binding} = req} = Stun.decode(wire, @creds.remote_ice_pwd)
    # RFC 8445 pt.7.2.2: peer ufrag first, then local (remote:local).
    assert req.attrs.username == "cli:svr"
    assert req.attrs.priority == <<12_345::32>>
    assert Map.has_key?(req.attrs, :ice_controlled)
  end

  test "connectivity_check detects role attributes" do
    req = %Stun{attrs: %{ice_controlling: <<0::64>>}}
    assert Binding.connectivity_check?(req)
    refute Binding.use_candidate?(req)
  end

  test "build_success echoes controlled role on connectivity check" do
    req = %Stun{
      class: :request,
      method: :binding,
      transactionid: 1,
      attrs: %{ice_controlling: <<0::64>>}
    }

    wire = Binding.build_success(req, {{127, 0, 0, 1}, 5000}, @creds)
    assert {:ok, resp} = Stun.decode(wire, @creds.ice_pwd)
    assert resp.attrs.xor_mapped_address == {{127, 0, 0, 1}, 5000}
    assert Map.has_key?(resp.attrs, :ice_controlled)
  end
end
