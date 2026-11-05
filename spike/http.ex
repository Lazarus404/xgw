defmodule XGW.Spike.HTTP do
  @moduledoc """
  Plug router for the browser spike: static index, SDP offer/answer, trickle ICE.
  """
  use Plug.Router

  plug :match
  plug :dispatch

  get "/" do
    index = Path.join(:code.priv_dir(:xgw), "spike/index.html")

    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_content_type("text/html")
    |> send_file(200, index)
  end

  post "/offer" do
    case read_body(conn) do
      {:ok, body, conn} ->
        codec = codec_from_conn(conn)

        case spike_call(fn -> XGW.Spike.Server.answer(body, codec: codec) end) do
          {:ok, answer} when is_binary(answer) ->
            conn
            |> put_resp_header("cache-control", "no-store")
            |> put_resp_content_type("application/sdp")
            |> send_resp(200, answer)

          {:ok, {:error, reason}} ->
            send_resp(conn, 500, "apply failed: #{inspect(reason)}")

          {:error, status, msg} ->
            send_resp(conn, status, msg)
        end

      {:error, reason} ->
        send_resp(conn, 400, "bad request: #{inspect(reason)}")
    end
  end

  post "/candidate" do
    case read_body(conn) do
      {:ok, body, conn} ->
        with {:ok, params} <- decode_json(body),
             :ok <- validate_candidate_params(params) do
          case spike_call(fn ->
                 XGW.Spike.Server.add_remote_candidate(normalize_candidate_params(params))
               end) do
            {:ok, :ok} ->
              conn
              |> put_resp_header("cache-control", "no-store")
              |> send_resp(204, "")

            {:ok, {:error, reason}} ->
              send_resp(conn, 400, "candidate rejected: #{inspect(reason)}")

            {:error, status, msg} ->
              send_resp(conn, status, msg)
          end
        else
          {:error, reason} ->
            send_resp(conn, 400, "bad candidate: #{inspect(reason)}")
        end

      {:error, reason} ->
        send_resp(conn, 400, "bad request: #{inspect(reason)}")
    end
  end

  get "/candidates" do
    conn = fetch_query_params(conn)

    since =
      case conn.query_params["since"] do
        nil -> 0
        s -> String.to_integer(s)
      end

    case spike_call(fn -> XGW.Spike.Server.local_candidates_since(since) end) do
      {:ok, payload} ->
        body = JSON.encode!(payload)

        conn
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_content_type("application/json")
        |> send_resp(200, body)

      {:error, status, msg} ->
        send_resp(conn, status, msg)
    end
  end

  get "/status" do
    st =
      case spike_call(fn -> XGW.Spike.Server.status() end) do
        {:ok, status} -> status
        {:error, _, _} -> %{peer: nil, dtls: false, rtp_logged?: false}
      end

    body =
      "dtls=#{if st.dtls, do: 1, else: 0} rtp=#{if st.rtp_logged?, do: 1, else: 0} sctp=#{if Map.get(st, :sctp), do: 1, else: 0} dc=#{if Map.get(st, :dc_echoed?), do: 1, else: 0} peer=#{format_peer(st.peer)} trickle=#{length(Map.get(st, :trickle, []))} remote_trickle=#{Map.get(st, :remote_trickle, 0)}"

    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_content_type("text/plain")
    |> send_resp(200, body)
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  defp spike_call(fun) do
    case fun.() do
      :ok -> {:ok, :ok}
      other -> {:ok, other}
    end
  catch
    :exit, {:noproc, _} -> {:error, 503, "spike server not running"}
    :exit, _ -> {:error, 503, "spike server unavailable"}
  end

  defp decode_json(body) do
    case JSON.decode(body) do
      {:ok, map} when is_map(map) -> {:ok, map}
      {:ok, _} -> {:error, :invalid_json}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_candidate_params(%{"end_of_candidates" => true} = params) do
    if Map.has_key?(params, "mid"), do: :ok, else: {:error, :missing_mid}
  end

  defp validate_candidate_params(%{"candidate" => c} = params) when is_binary(c) do
    if Map.has_key?(params, "mid"), do: :ok, else: {:error, :missing_mid}
  end

  defp validate_candidate_params(_), do: {:error, :invalid_candidate}

  defp normalize_candidate_params(%{"end_of_candidates" => true} = params) do
    %{end_of_candidates: true, mid: Map.fetch!(params, "mid")}
  end

  defp normalize_candidate_params(%{"candidate" => c} = params) when is_binary(c) do
    %{candidate: c, mid: Map.fetch!(params, "mid")}
  end

  defp format_peer({ip, port}), do: "#{ip |> :inet.ntoa() |> to_string()}:#{port}"
  defp format_peer(nil), do: "-"

  defp codec_from_conn(conn) do
    case Plug.Conn.get_req_header(conn, "x-spike-codec") do
      [value | _] -> XGW.Spike.SDP.normalize_codec(value)
      [] -> :opus
    end
  end
end
