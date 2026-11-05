defmodule XGW.Test.StunFixtures do
  @moduledoc false

  alias XMediaLib.Stun

  @doc false
  def binding_success(attrs \\ [])

  def binding_success(attrs) when is_list(attrs) do
    attrs = Map.new(attrs)

    {mapped_ip, mapped_port} =
      Map.get(attrs, :xor_mapped_address, {{203, 0, 113, 50}, 54_321})

    %Stun{
      class: :success,
      method: :binding,
      transactionid: Map.get(attrs, :transactionid, :rand.uniform(0xFFFFFFFFFFFF)),
      fingerprint: true,
      attrs: %{xor_mapped_address: {mapped_ip, mapped_port}}
    }
  end

  @doc false
  def binding_success(attrs) when is_map(attrs) do
    binding_success(Map.to_list(attrs))
  end

  @doc false
  def binding_success_wire(attrs \\ []) do
    attrs |> Map.new() |> binding_success() |> Stun.encode()
  end

  @doc false
  def connectivity_check_request(opts) when is_list(opts) do
    opts = Map.new(opts)
    pwd = Map.fetch!(opts, :pwd)
    username = Map.fetch!(opts, :username)

    attrs =
      %{
        username: username,
        priority: Map.get(opts, :priority, <<1::32>>)
      }
      |> maybe_put_role(opts)
      |> maybe_put_use_candidate(Map.get(opts, :use_candidate, false))

    %Stun{
      class: :request,
      method: :binding,
      transactionid: Map.get(opts, :transactionid, :rand.uniform(0xFFFFFFFFFFFF)),
      integrity: true,
      key: pwd,
      fingerprint: true,
      attrs: attrs
    }
  end

  @doc false
  def connectivity_check_wire(opts) when is_list(opts) do
    opts |> connectivity_check_request() |> Stun.encode()
  end

  defp maybe_put_role(attrs, opts) do
    cond do
      Map.has_key?(opts, :ice_controlling) ->
        Map.put(attrs, :ice_controlling, Map.fetch!(opts, :ice_controlling))

      Map.has_key?(opts, :ice_controlled) ->
        Map.put(attrs, :ice_controlled, Map.fetch!(opts, :ice_controlled))

      true ->
        Map.put(attrs, :ice_controlling, <<0, 0, 0, 0, 0, 0, 0, 1>>)
    end
  end

  defp maybe_put_use_candidate(attrs, true), do: Map.put(attrs, :use_candidate, <<>>)
  defp maybe_put_use_candidate(attrs, _), do: attrs

  @doc false
  def respond_to_binding(request_wire, mapped \\ {{203, 0, 113, 50}, 54_321}) do
    with {:ok, req} <- Stun.decode(request_wire) do
      {:ok,
       binding_success(transactionid: req.transactionid, xor_mapped_address: mapped)
       |> Stun.encode()}
    end
  end

  @doc false
  def start_echo_server(opts \\ []) do
    mapped = Keyword.get(opts, :mapped, {{203, 0, 113, 50}, 54_321})
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(sock)

    pid =
      spawn_link(fn ->
        echo_loop(sock, mapped)
      end)

    {port, pid, sock}
  end

  defp echo_loop(sock, mapped) do
    case recv_datagram(sock) do
      {:ok, reply_ip, reply_port, data} ->
        case respond_to_binding(data, mapped) do
          {:ok, resp} -> :gen_udp.send(sock, reply_ip, reply_port, resp)
          _ -> :ok
        end

        echo_loop(sock, mapped)

      _ ->
        echo_loop(sock, mapped)
    end
  end

  defp recv_datagram(sock) do
    case :gen_udp.recv(sock, 2048, 5_000) do
      {:ok, {ip, port, data}} -> {:ok, ip, port, data}
      {:ok, data} -> {:ok, {127, 0, 0, 1}, 0, data}
      other -> other
    end
  end
end
