defmodule XGW.ICE do
  @moduledoc """
  Shared Interactive Connectivity Establishment (ICE) types and pure helpers.

  ## What ICE is

  Home and office networks usually put devices behind a **NAT**: the address
  your laptop thinks it has is not the address the public internet sees.
  Firewalls may also block inbound UDP. **ICE** (RFC 8445) is the WebRTC
  procedure for discovering workable address/port pairs (**candidates**),
  probing them with **STUN Binding** checks, and nominating one pair for media.

  Candidate kinds you will see in XGW:

  - **host** -- a local interface address on this machine
  - **srflx** (server reflexive) -- the public address discovered via STUN
  - **relay** -- an address on a TURN server that forwards packets for you
  - **prflx** (peer reflexive) -- learned from the far side during a check

  This module holds types and pure functions used by both **ICE-lite**
  (`XGW.ICE.Lite`, controlled-only responses) and **ICE-full**
  (`XGW.ICE.Full`, gather + checklist + outbound checks). Gathering lives in
  `XGW.ICE.Gather`; pair state in `XGW.ICE.Checklist`. Candidates on the wire
  are `%XMediaLib.SDP.Candidate{}` structs.

  ## RFCs

  * RFC 8445 -- ICE (candidates, roles, priorities, foundations, nomination)
  * RFC 8489 -- STUN Binding used as connectivity checks
  * RFC 8656 -- TURN relay candidates (gather/checklist integration)
  """

  alias XMediaLib.SDP.Candidate
  alias XMediaLib.SDP.Media

  @typedoc "ICE candidate type (RFC 8445)."
  @type candidate_type :: :host | :srflx | :relay | :prflx

  @typedoc "ICE candidate transport."
  @type transport :: :udp | :tcp

  @typedoc "ICE controlling vs controlled role."
  @type role :: :controlling | :controlled

  @typedoc "ICE agent connection phase (full ICE state machine)."
  @type ice_phase :: :gathering | :checking | :connected | :completed | :failed | :disconnected

  @typedoc "Remote UDP endpoint `{ip, port}`."
  @type endpoint :: {:inet.ip_address(), :inet.port_number()}

  @doc """
  Maps SDP candidate type string to an atom.

  ## Examples

      iex> XGW.ICE.type_atom("host")
      :host

      iex> XGW.ICE.type_atom("nope")
      nil
  """
  @spec type_atom(String.t()) :: candidate_type() | nil
  def type_atom("host"), do: :host
  def type_atom("srflx"), do: :srflx
  def type_atom("relay"), do: :relay
  def type_atom("prflx"), do: :prflx
  def type_atom(_), do: nil

  @doc """
  Maps SDP transport string to an atom.

  ## Examples

      iex> XGW.ICE.transport_atom("UDP")
      :udp
  """
  @spec transport_atom(String.t()) :: transport() | nil
  def transport_atom("udp"), do: :udp
  def transport_atom("tcp"), do: :tcp
  def transport_atom(t) when is_binary(t), do: transport_atom(String.downcase(t))
  def transport_atom(_), do: nil

  @doc """
  Returns true when the candidate has a foundation and allowed type.

  ## Examples

      iex> XGW.ICE.valid?(%XMediaLib.SDP.Candidate{
      ...>   foundation: "1", type: "host", ip: "192.0.2.1", port: 1
      ...> })
      true

      iex> XGW.ICE.valid?(%XMediaLib.SDP.Candidate{foundation: nil, type: "host"})
      false
  """
  @spec valid?(Candidate.t()) :: boolean()
  def valid?(%Candidate{foundation: foundation, type: type}) do
    foundation not in [nil, ""] and type in ["host", "srflx", "relay", "prflx"]
  end

  @doc """
  RFC 8445 section 6.1.2.1 pair priority from controlling/controlled priorities.

  ## Examples

      iex> XGW.ICE.pair_priority(:controlling, 100, 50)
      Bitwise.bsl(50, 32) + 2 * 100 + 1

      iex> XGW.ICE.pair_priority(:controlled, 100, 50)
      Bitwise.bsl(50, 32) + 2 * 100 + 0
  """
  @spec pair_priority(role(), non_neg_integer(), non_neg_integer()) :: non_neg_integer()
  def pair_priority(role, local_priority, remote_priority) do
    {controlling, controlled} =
      case role do
        :controlling -> {local_priority, remote_priority}
        :controlled -> {remote_priority, local_priority}
      end

    min_p = min(controlling, controlled)
    max_p = max(controlling, controlled)
    Bitwise.bsl(min_p, 32) + 2 * max_p + if(controlling > controlled, do: 1, else: 0)
  end

  @doc """
  Builds a peer-reflexive remote candidate from an inbound check source address.
  """
  @spec prflx_candidate(endpoint(), non_neg_integer(), String.t()) :: Candidate.t()
  def prflx_candidate({ip, port}, priority, transport \\ "udp") do
    transport = String.downcase(transport)
    ip_str = format_ip(ip)

    %Candidate{
      foundation: foundation("prflx", ip, transport),
      component_id: 1,
      transport: transport,
      priority: priority,
      ip: ip_str,
      port: port,
      type: "prflx"
    }
  end

  @doc """
  RFC 8445 section 5.1.1 candidate foundation (stable for agent lifetime).

  Hash of `(type, base_ip, transport)` masked to 32 bits.

  ## Examples

      iex> XGW.ICE.foundation("host", {192, 0, 2, 1}, "udp") ==
      ...>   XGW.ICE.foundation("host", "192.0.2.1", "UDP")
      true
  """
  @spec foundation(String.t(), :inet.ip_address() | String.t(), String.t()) :: String.t()
  def foundation(type, ip, transport) when is_binary(type) and is_binary(transport) do
    ip_str = if is_tuple(ip), do: format_ip(ip), else: ip
    transport = String.downcase(transport)

    Bitwise.band(:erlang.phash2({type, ip_str, transport}), 0xFFFFFFFF)
    |> Integer.to_string()
  end

  @doc """
  Formats an IPv4/IPv6 tuple as a dotted/colon string for SDP.

  ## Examples

      iex> XGW.ICE.format_ip({192, 0, 2, 1})
      "192.0.2.1"
  """
  @spec format_ip(:inet.ip_address()) :: String.t()
  def format_ip(ip), do: ip |> :inet.ntoa() |> to_string()

  @doc """
  SDP `a=candidate:` attribute value (without the `a=` prefix).

  ## Examples

      iex> c = %XMediaLib.SDP.Candidate{
      ...>   foundation: "1",
      ...>   component_id: 1,
      ...>   transport: "udp",
      ...>   priority: 100,
      ...>   ip: "192.0.2.1",
      ...>   port: 5000,
      ...>   type: "host"
      ...> }
      iex> XGW.ICE.candidate_line(c)
      "candidate:1 1 UDP 100 192.0.2.1 5000 typ host"
  """
  @spec candidate_line(Candidate.t()) :: String.t()
  def candidate_line(%Candidate{} = c) do
    transport = String.upcase(c.transport)
    base = "candidate:#{c.foundation} #{c.component_id} #{transport} #{c.priority} #{c.ip} #{c.port} typ #{c.type}"

    if c.rest in [nil, ""] do
      base
    else
      base <> " " <> c.rest
    end
  end

  @doc """
  Merges remote candidates: dedup by `{foundation, component_id, ip, port}`,
  sort descending by priority (RFC 8445).

  ## Examples

      iex> low = %XMediaLib.SDP.Candidate{
      ...>   foundation: "1", component_id: 1, transport: "udp",
      ...>   priority: 100, ip: "192.0.2.1", port: 5000, type: "host"
      ...> }
      iex> high = %{low | foundation: "2", priority: 200, ip: "192.0.2.2", port: 5001}
      iex> Enum.map(XGW.ICE.merge_remote([low], [high, high]), & &1.priority)
      [200, 100]
  """
  @spec merge_remote([Candidate.t()], [Candidate.t()]) :: [Candidate.t()]
  def merge_remote(existing, incoming) do
    (existing ++ incoming)
    |> Enum.uniq_by(&candidate_key/1)
    |> Enum.sort_by(& &1.priority, :desc)
  end

  @doc """
  Returns `{ip, port}` for a parsed candidate.

  ## Examples

      iex> XGW.ICE.endpoint(%XMediaLib.SDP.Candidate{ip: "192.0.2.1", port: 5000})
      {{192, 0, 2, 1}, 5000}
  """
  @spec endpoint(Candidate.t()) :: endpoint()
  def endpoint(%Candidate{ip: ip, port: port}) do
    case parse_ip(ip) do
      {:ok, tuple} -> {tuple, port}
      :error -> {{0, 0, 0, 0}, port}
    end
  end

  @doc """
  True when `candidate` has a parseable, non-unspecified IP (not mDNS / 0.0.0.0).

  ## Examples

      iex> XGW.ICE.usable_endpoint?(%XMediaLib.SDP.Candidate{ip: "192.0.2.1", port: 1})
      true

      iex> XGW.ICE.usable_endpoint?(%XMediaLib.SDP.Candidate{ip: "0.0.0.0", port: 1})
      false
  """
  @spec usable_endpoint?(Candidate.t()) :: boolean()
  def usable_endpoint?(%Candidate{} = cand) do
    case endpoint(cand) do
      {{0, 0, 0, 0}, _} -> false
      {{0, 0, 0, 0, 0, 0, 0, 0}, _} -> false
      _ -> true
    end
  end

  @doc """
  True when both candidates resolve to the same IP version (IPv4 or IPv6).

  ## Examples

      iex> a = %XMediaLib.SDP.Candidate{ip: "192.0.2.1", port: 1}
      iex> b = %XMediaLib.SDP.Candidate{ip: "198.51.100.1", port: 2}
      iex> XGW.ICE.same_address_family?(a, b)
      true
  """
  @spec same_address_family?(Candidate.t(), Candidate.t()) :: boolean()
  def same_address_family?(a, b) do
    {ip_a, _} = endpoint(a)
    {ip_b, _} = endpoint(b)
    tuple_size(ip_a) == tuple_size(ip_b) and usable_endpoint?(a) and usable_endpoint?(b)
  end

  defp parse_ip(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, tuple} -> {:ok, tuple}
      {:error, _} -> :error
    end
  end

  defp parse_ip(ip) when is_tuple(ip), do: {:ok, ip}
  defp parse_ip(_), do: :error

  @doc """
  RFC 8445 section 5.1.2 type preference for a candidate type.

  ## Examples

      iex> XGW.ICE.type_preference(:host)
      126

      iex> XGW.ICE.type_preference(:relay)
      0
  """
  @spec type_preference(candidate_type()) :: non_neg_integer()
  def type_preference(:host), do: 126
  def type_preference(:srflx), do: 100
  def type_preference(:prflx), do: 110
  def type_preference(:relay), do: 0

  @doc """
  RFC 8445 section 5.1.2 candidate priority from type, component, local preference.

  ## Examples

      iex> XGW.ICE.candidate_priority(:host, 1, 65_535) == XGW.ICE.host_priority(1)
      true
  """
  @spec candidate_priority(candidate_type(), non_neg_integer(), non_neg_integer()) ::
          non_neg_integer()
  def candidate_priority(type, component_id, local_preference) do
    type_preference(type) * Bitwise.bsl(1, 24) + local_preference * Bitwise.bsl(1, 8) +
      (256 - component_id)
  end

  @doc """
  RFC 8445 section 5.1.2 host candidate priority.

  `local_preference` defaults to 65535 (single interface).

  ## Examples

      iex> XGW.ICE.host_priority(1, 65_535) == XGW.ICE.candidate_priority(:host, 1, 65_535)
      true
  """
  @spec host_priority(non_neg_integer(), non_neg_integer()) :: non_neg_integer()
  def host_priority(component_id, local_preference \\ 65_535) do
    candidate_priority(:host, component_id, local_preference)
  end

  @doc """
  Local preference encoded in a host candidate priority.
  """
  @spec local_preference_from_priority(Candidate.t()) :: non_neg_integer()
  def local_preference_from_priority(%Candidate{type: "host", priority: p, component_id: c}) do
    div(p - type_preference(:host) * Bitwise.bsl(1, 24) - (256 - c), Bitwise.bsl(1, 8))
  end

  @doc """
  Maps answerer DTLS `setup` to ICE role for full-ICE answers.

  XGW convention (not RFC 8445 pt.5.1.1): offer `actpass` + answer `passive`
  (DTLS server) -> ICE `:controlled`; offer `actpass` + answer `active` ->
  `:controlling`. ICE-lite agents are always controlled per RFC 8445
  pt.6.1.1 regardless of this helper.

  ## Examples

      iex> XGW.ICE.role(:actpass, :passive)
      {:ok, :controlled}

      iex> XGW.ICE.role(:actpass, :active)
      {:ok, :controlling}

      iex> XGW.ICE.role(:active, :passive)
      {:error, :unsupported_setup}
  """
  @spec role(Media.setup(), Media.setup()) :: {:ok, role()} | {:error, :unsupported_setup}
  def role(:actpass, :passive), do: {:ok, :controlled}
  def role(:actpass, :active), do: {:ok, :controlling}
  def role(_, _), do: {:error, :unsupported_setup}

  @doc """
  Coerces trickle input to `%Candidate{}`.
  """
  @spec coerce_candidate(Candidate.t() | String.t()) :: {:ok, Candidate.t()} | {:error, term()}
  def coerce_candidate(%Candidate{} = c), do: {:ok, c}

  def coerce_candidate(line) when is_binary(line) do
    cand = XMediaLib.SDP.Parser.Helpers.parse_candidate(line)
    if valid?(cand), do: {:ok, cand}, else: {:error, :invalid_candidate}
  rescue
    _ -> {:error, :invalid_candidate}
  end

  @doc """
  Validates trickle `:mid` / `:mline_index` against bundled mids when present.
  """
  @spec validate_mid(map(), [String.t()]) :: :ok | {:error, :media_not_found}
  def validate_mid(%{mid: mid}, mids) when is_binary(mid) and mids != [] do
    if mid in mids, do: :ok, else: {:error, :media_not_found}
  end

  def validate_mid(%{mline_index: idx}, mids) when is_integer(idx) and mids != [] do
    if idx < length(mids), do: :ok, else: {:error, :media_not_found}
  end

  def validate_mid(_, _), do: :ok

  defp candidate_key(%Candidate{foundation: f, component_id: c, ip: ip, port: port}) do
    {f, c, ip, port}
  end
end
