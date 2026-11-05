defmodule XGW.ICE.Gather do
  @moduledoc """
  Discovers ICE candidates: host, server-reflexive (srflx), and TURN relay.

  ## Candidate gathering in plain terms

  Before checks can run, each side must advertise addresses it might be
  reachable on:

  1. **Host** -- read local NIC addresses (synchronous; always available).
  2. **srflx** -- ask a STUN server "what public address do you see?" so peers
     behind NAT learn a candidate that might work on the open internet.
  3. **relay** -- ask a TURN server to allocate a relay address that always
     works when direct paths fail (at the cost of an extra hop).

  Host gather is synchronous. srflx and relay honor `gather_timeout_ms`
  (default 3000). Prefer waiting for gather before publishing answer SDP;
  host-only answers remain valid when STUN/TURN is slow or unconfigured.

  ## RFCs

  * RFC 8445 -- host / srflx / relay candidate gathering
  * RFC 8489 -- STUN Binding for server-reflexive discovery
  * RFC 8656 -- TURN Allocate for relay candidates
  """

  alias XGW.{ICE, TURN.Client}
  alias XMediaLib.SDP.Candidate
  alias XMediaLib.Stun

  @local_pref_step 256
  @max_local_pref 65_535
  @default_gather_timeout_ms 3_000

  @doc """
  Resolves host IP addresses for candidate advertisement.

  Options:

    * `:advertised_ips` - explicit list (wins over all other sources)
    * `:advertised_ip` - single override
    * `:include_loopback` - include `{127,0,0,1}` when auto-detecting (default `true`)
    * `:getifaddrs` - injectable `fn -> {:ok, ifaddrs} | {:error, _}` for tests
  """
  @spec host_addresses(keyword()) :: [:inet.ip_address()]
  def host_addresses(opts \\ []) do
    ips =
      cond do
        ips = Keyword.get(opts, :advertised_ips) ->
          List.wrap(ips)

        ip = Keyword.get(opts, :advertised_ip) ->
          [ip]

        true ->
          detect_addresses(opts)
      end

    ips
    |> Enum.uniq()
    |> sort_addresses(Keyword.get(opts, :include_loopback, true))
  end

  @doc """
  Builds host `%Candidate{}` structs for one UDP bind port.
  """
  @spec host_candidates({:inet.ip_address(), :inet.port_number()}, keyword()) :: [Candidate.t()]
  def host_candidates({_bound_ip, port}, opts \\ []) when is_integer(port) do
    build_host_candidates(port, "udp", opts)
  end

  @doc """
  Builds passive ICE-TCP host candidates (RFC 6544 `tcptype passive`).
  """
  @spec tcp_passive_candidates({:inet.ip_address(), :inet.port_number()}, keyword()) ::
          [Candidate.t()]
  def tcp_passive_candidates({_bound_ip, port}, opts \\ []) when is_integer(port) do
    build_host_candidates(port, "tcp", Keyword.put(opts, :tcp_passive, true))
  end

  defp build_host_candidates(port, transport, opts) do
    opts
    |> host_addresses()
    |> Enum.with_index()
    |> Enum.map(fn {ip, idx} ->
      local_pref = max(0, @max_local_pref - idx * @local_pref_step)
      rest = if Keyword.get(opts, :tcp_passive), do: "tcptype passive", else: nil

      %Candidate{
        foundation: ICE.foundation("host", ip, transport),
        component_id: 1,
        transport: transport,
        priority: ICE.host_priority(1, local_pref),
        ip: ICE.format_ip(ip),
        port: port,
        type: "host",
        rest: rest
      }
    end)
    |> Enum.sort_by(& &1.priority, :desc)
  end

  @doc """
  Gathers host candidates for a bound UDP socket (alias for `host_candidates/2`).
  """
  @spec gather_host({:inet.ip_address(), :inet.port_number()}, keyword()) :: [Candidate.t()]
  defdelegate gather_host(sockname, opts \\ []), to: __MODULE__, as: :host_candidates

  @doc """
  Parses a STUN server URI (`stun:host:port`) to `{ip, port}`.
  """
  @spec parse_stun_server(String.t()) :: {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def parse_stun_server("stun:" <> rest), do: Client.parse_server_host(rest, :invalid_stun_server)
  def parse_stun_server(_), do: {:error, :invalid_stun_server}

  @doc """
  Parses a TURN server URI (`turn:host:port`) to `{ip, port}`.
  """
  @spec parse_turn_server(String.t()) :: {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  defdelegate parse_turn_server(uri), to: Client

  @doc """
  Parses host[:port] from a URI body (shared by STUN/TURN parsers).
  """
  defdelegate parse_server_host(rest, error \\ :invalid_server), to: Client

  @doc """
  Plain RFC 8489 STUN Binding request wire (no ICE credentials).
  """
  @spec stun_binding_request() :: binary()
  def stun_binding_request do
    %Stun{
      class: :request,
      method: :binding,
      transactionid: :rand.uniform(0xFFFFFFFFFFFF),
      fingerprint: true,
      attrs: %{}
    }
    |> Stun.encode()
  end

  @doc """
  Builds an srflx candidate linked to a host base (same foundation, raddr/rport).
  """
  @spec build_srflx({:inet.ip_address(), :inet.port_number()}, Candidate.t(), non_neg_integer()) ::
          Candidate.t()
  def build_srflx({mapped_ip, mapped_port}, %Candidate{} = host, local_preference) do
    %Candidate{
      foundation: host.foundation,
      component_id: host.component_id,
      transport: host.transport,
      priority: ICE.candidate_priority(:srflx, host.component_id, local_preference),
      ip: ICE.format_ip(mapped_ip),
      port: mapped_port,
      type: "srflx",
      rest: "raddr #{host.ip} rport #{host.port}"
    }
  end

  @doc """
  Derives srflx `%Candidate{}` from a Binding success and host base.
  """
  @spec srflx_from_response(Stun.t(), Candidate.t()) :: {:ok, Candidate.t()} | {:error, term()}
  def srflx_from_response(
        %Stun{class: :success, method: :binding, attrs: attrs},
        %Candidate{} = host
      ) do
    case Map.get(attrs, :xor_mapped_address) do
      {ip, port} when is_integer(port) ->
        local_pref = ICE.local_preference_from_priority(host)
        {:ok, build_srflx({ip, port}, host, local_pref)}

      _ ->
        {:error, :no_mapped_address}
    end
  end

  def srflx_from_response(_, _), do: {:error, :invalid_stun_response}

  @doc """
  Queries one STUN server for srflx using injectable `:send_recv`.

  `:send_recv` is `fn request_wire, {stun_ip, stun_port} -> {:ok, response_wire} | {:error, _}`.
  """
  @spec query_srflx(
          {:inet.ip_address(), :inet.port_number()},
          Candidate.t(),
          String.t() | {:inet.ip_address(), :inet.port_number()},
          keyword()
        ) :: {:ok, Candidate.t()} | {:error, term()}
  def query_srflx(_sockname, host_base, stun_server, opts) do
    with {:ok, endpoint} <- normalize_stun_endpoint(stun_server),
         send_recv when is_function(send_recv, 2) <- Keyword.get(opts, :send_recv),
         wire <- stun_binding_request(),
         {:ok, resp} <- send_recv.(wire, endpoint),
         {:ok, %Stun{} = stun} <- Stun.decode(resp) do
      srflx_from_response(stun, host_base)
    else
      nil -> {:error, :missing_send_recv}
      {:error, _} = err -> err
      _ -> {:error, :stun_query_failed}
    end
  end

  @doc """
  Builds a relay `%Candidate{}` from a TURN relayed transport address.
  """
  @spec build_relay({:inet.ip_address(), :inet.port_number()}, non_neg_integer()) :: Candidate.t()
  def build_relay({relay_ip, relay_port}, local_preference \\ @max_local_pref) do
    %Candidate{
      foundation: ICE.foundation("relay", relay_ip, "udp"),
      component_id: 1,
      transport: "udp",
      priority: ICE.candidate_priority(:relay, 1, local_preference),
      ip: ICE.format_ip(relay_ip),
      port: relay_port,
      type: "relay"
    }
  end

  @doc """
  Derives relay `%Candidate{}` from a successful TURN Allocate response.
  """
  @spec relay_from_allocate(Stun.t(), non_neg_integer()) :: {:ok, Candidate.t()} | {:error, term()}
  def relay_from_allocate(stun, local_preference \\ @max_local_pref)

  def relay_from_allocate(
        %Stun{class: :success, method: :allocate, attrs: attrs},
        local_preference
      ) do
    case Map.get(attrs, :xor_relayed_address) do
      {ip, port} when is_integer(port) ->
        {:ok, build_relay({ip, port}, local_preference)}

      _ ->
        {:error, :no_relayed_address}
    end
  end

  def relay_from_allocate(_, _), do: {:error, :invalid_allocate_response}

  @doc """
  Queries one TURN server for a relay candidate using injectable `:send_recv`.

  Returns `{:ok, %{candidate: cand, allocation: alloc}}` on success.
  """
  @spec query_relay(
          {:inet.ip_address(), :inet.port_number()},
          String.t() | {:inet.ip_address(), :inet.port_number()},
          keyword()
        ) :: {:ok, %{candidate: Candidate.t(), allocation: Client.allocation()}} | {:error, term()}
  def query_relay(_sockname, turn_server, opts) do
    with {:ok, endpoint} <- normalize_turn_endpoint(turn_server),
         send_recv when is_function(send_recv, 2) <- Keyword.get(opts, :send_recv),
         cred_opts <- Keyword.get(opts, :turn_credentials, []),
         local_pref <- Keyword.get(opts, :relay_local_preference, @max_local_pref),
         {:ok, allocation} <- Client.allocate(send_recv, endpoint, cred_opts),
         {:ok, cand} <- relay_from_allocate(allocate_success(allocation), local_pref) do
      {:ok, %{candidate: cand, allocation: allocation}}
    else
      nil -> {:error, :missing_send_recv}
      {:error, _} = err -> err
      _ -> {:error, :turn_query_failed}
    end
  end

  @doc """
  Gathers relay candidates concurrently (one attempt per `turn_servers` entry).
  """
  @spec gather_relay({:inet.ip_address(), :inet.port_number()}, keyword()) :: [
          %{candidate: Candidate.t(), allocation: Client.allocation()}
        ]
  def gather_relay(sockname, opts) do
    turn_servers = Keyword.get(opts, :turn_servers, [])
    timeout = Keyword.get(opts, :query_timeout_ms, @default_gather_timeout_ms)

    if turn_servers == [] do
      []
    else
      turn_servers
      |> Enum.map(fn turn ->
        Task.async(fn -> query_relay(sockname, turn, opts) end)
      end)
      |> Task.yield_many(timeout)
      |> Enum.flat_map(fn
        {task, nil} ->
          Task.shutdown(task, :brutal_kill)
          []

        {_task, {:ok, {:ok, result}}} ->
          [result]

        _ ->
          []
      end)
      |> Enum.uniq_by(fn %{candidate: c} -> {c.foundation, c.ip, c.port} end)
      |> Enum.sort_by(fn %{candidate: c} -> c.priority end, :desc)
    end
  end

  @doc """
  Gathers host candidates and waits up to `gather_timeout_ms` for srflx and relay.

  srflx and relay run concurrently under one timeout budget (not sequential).

  Returns `%{host: [...], srflx: [...], relay: [...]}`.
  """
  @spec gather_with_timeout({:inet.ip_address(), :inet.port_number()}, keyword()) :: %{
          host: [Candidate.t()],
          srflx: [Candidate.t()],
          relay: [Candidate.t()]
        }
  def gather_with_timeout(sockname, opts \\ []) do
    hosts = host_candidates(sockname, opts)
    timeout = Keyword.get(opts, :gather_timeout_ms, @default_gather_timeout_ms)
    merged_opts = Keyword.merge(opts, query_timeout_ms: timeout)

    srflx_task = Task.async(fn -> gather_srflx(sockname, hosts, merged_opts) end)

    relay_task =
      Task.async(fn ->
        gather_relay(sockname, merged_opts) |> Enum.map(& &1.candidate)
      end)

    srflx =
      case Task.yield(srflx_task, timeout) do
        {:ok, result} -> result
        nil ->
          Task.shutdown(srflx_task, :brutal_kill)
          []
      end

    relay =
      case Task.yield(relay_task, timeout) do
        {:ok, result} -> result
        nil ->
          Task.shutdown(relay_task, :brutal_kill)
          []
      end

    %{host: hosts, srflx: srflx, relay: relay}
  end

  defp normalize_turn_endpoint({ip, port}) when is_tuple(ip), do: {:ok, {ip, port}}
  defp normalize_turn_endpoint(uri) when is_binary(uri), do: parse_turn_server(uri)

  defp normalize_stun_endpoint({ip, port}) when is_tuple(ip), do: {:ok, {ip, port}}
  defp normalize_stun_endpoint(uri) when is_binary(uri), do: parse_stun_server(uri)

  @doc """
  Gathers srflx candidates for all `(host, stun_server)` pairs concurrently.
  """
  @spec gather_srflx(
          {:inet.ip_address(), :inet.port_number()},
          [Candidate.t()],
          keyword()
        ) :: [Candidate.t()]
  def gather_srflx(_sockname, host_bases, opts) do
    stun_servers = Keyword.get(opts, :stun_servers, [])
    timeout = Keyword.get(opts, :query_timeout_ms, @default_gather_timeout_ms)

    if stun_servers == [] or host_bases == [] do
      []
    else
      host_bases
      |> pairs(stun_servers)
      |> Enum.map(fn {host, stun} ->
        Task.async(fn -> query_srflx({{0, 0, 0, 0}, 0}, host, stun, opts) end)
      end)
      |> Task.yield_many(timeout)
      |> Enum.flat_map(fn
        {task, nil} ->
          Task.shutdown(task, :brutal_kill)
          []

        {_task, {:ok, {:ok, cand}}} ->
          [cand]

        _ ->
          []
      end)
      |> Enum.uniq_by(&{&1.foundation, &1.ip, &1.port})
      |> Enum.sort_by(& &1.priority, :desc)
    end
  end

  defp allocate_success(%{relay: {ip, port}}) do
    %Stun{
      class: :success,
      method: :allocate,
      attrs: %{xor_relayed_address: {ip, port}}
    }
  end

  defp pairs(hosts, stun_servers) do
    for h <- hosts, s <- stun_servers, do: {h, s}
  end

  defp detect_addresses(opts) do
    getifaddrs = Keyword.get(opts, :getifaddrs, &:inet.getifaddrs/0)

    lan =
      case getifaddrs.() do
        {:ok, ifs} ->
          ifs
          |> Enum.reject(fn {name, _} ->
            name |> to_string() |> String.starts_with?("lo")
          end)
          |> Enum.flat_map(fn {_name, addrs} ->
            for {:addr, {a, b, c, d}} when a != 127 <- addrs, do: {a, b, c, d}
          end)

        _ ->
          []
      end

    loopback = if Keyword.get(opts, :include_loopback, true), do: [{127, 0, 0, 1}], else: []
    loopback ++ lan
  end

  defp sort_addresses(ips, include_loopback?) do
    ips
    |> Enum.sort_by(fn
      {127, 0, 0, 1} when include_loopback? -> {0, 0, 0, 0, 0}
      {a, b, c, d} -> {1, a, b, c, d}
    end)
  end
end
