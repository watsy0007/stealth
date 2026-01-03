defmodule Stealth.Protocol.Trojan.Client do
  @moduledoc """
  Trojan protocol client implementation.

  Provides functions to connect to Trojan servers and proxy traffic.
  """

  require Logger
  alias Stealth.Protocol.Trojan.{Protocol, Crypto}

  @doc """
  Connect to Trojan server and establish tunnel.

  ## Parameters
    - server_host: Trojan server hostname
    - server_port: Trojan server port
    - password: Trojan password
    - target_host: Target destination host
    - target_port: Target destination port
    - opts: Additional options

  ## Options
    - :ssl_opts - SSL/TLS options for server connection
    - :verify - Certificate verification mode (:verify_peer, :verify_none)
    - :initial_payload - Initial data to send after handshake

  ## Examples

      iex> Client.connect("trojan.example.com", 443, "password", "target.com", 80)
      {:ok, ssl_socket}
  """
  def connect(server_host, server_port, password, target_host, target_port, opts \\ []) do
    with {:ok, ssl_socket} <- connect_to_server(server_host, server_port, opts),
         {:ok, request} <- build_trojan_request(password, target_host, target_port, opts),
         :ok <- send_handshake(ssl_socket, request) do
      Logger.info(
        "Trojan tunnel established: #{server_host}:#{server_port} -> #{target_host}:#{target_port}"
      )

      {:ok, ssl_socket}
    else
      {:error, reason} = error ->
        Logger.error("Failed to establish Trojan tunnel: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Send data through established Trojan tunnel.

  ## Examples

      iex> Client.send_data(socket, "GET / HTTP/1.1\\r\\n\\r\\n")
      :ok
  """
  def send_data(socket, data) do
    Crypto.ssl_send(socket, data)
  end

  @doc """
  Receive data from Trojan tunnel.

  ## Examples

      iex> Client.recv_data(socket)
      {:ok, data}
  """
  def recv_data(socket, length \\ 0, timeout \\ 5000) do
    Crypto.ssl_recv(socket, length, timeout)
  end

  @doc """
  Close Trojan tunnel connection.

  ## Examples

      iex> Client.close(socket)
      :ok
  """
  def close(socket) do
    Crypto.ssl_close(socket)
  end

  @doc """
  Create HTTP proxy request through Trojan tunnel.

  ## Examples

      iex> Client.http_proxy_request(socket, "GET", "/", "example.com")
      {:ok, response}
  """
  def http_proxy_request(socket, method, path, host, headers \\ [], body \\ "") do
    request = build_http_request(method, path, host, headers, body)

    with :ok <- send_data(socket, request),
         {:ok, response} <- recv_data(socket) do
      {:ok, response}
    end
  end

  @doc """
  Proxy bidirectional data between local and remote socket.

  This function blocks until connection is closed.

  ## Examples

      iex> Client.proxy_bidirectional(local_socket, trojan_socket)
      :ok
  """
  def proxy_bidirectional(local_socket, trojan_socket) do
    task1 =
      Task.async(fn ->
        proxy_direction(local_socket, trojan_socket, "local->remote")
      end)

    task2 =
      Task.async(fn ->
        proxy_direction(trojan_socket, local_socket, "remote->local")
      end)

    # Wait for either direction to complete
    Task.yield_many([task1, task2], :infinity)
    Task.shutdown(task1, :brutal_kill)
    Task.shutdown(task2, :brutal_kill)

    :ok
  end

  # Private functions

  defp connect_to_server(host, port, opts) do
    ssl_opts = Keyword.get(opts, :ssl_opts, [])
    verify = Keyword.get(opts, :verify, :verify_peer)

    ssl_opts =
      Keyword.merge(
        [verify: verify],
        ssl_opts
      )

    Crypto.ssl_connect(host, port, ssl_opts)
  end

  defp build_trojan_request(password, target_host, target_port, opts) do
    initial_payload = Keyword.get(opts, :initial_payload, "")
    cmd = Keyword.get(opts, :cmd, :connect)

    # Try to parse target_host as IP address first
    address =
      case parse_ip(target_host) do
        {:ok, ip} -> ip
        :error -> target_host
      end

    Protocol.build_request(password, address, target_port, initial_payload, cmd)
  end

  defp send_handshake(socket, request) do
    Crypto.ssl_send(socket, request)
  end

  defp parse_ip(host) when is_binary(host) do
    charlist = String.to_charlist(host)

    case :inet.parse_address(charlist) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> :error
    end
  end

  defp build_http_request(method, path, host, headers, body) do
    default_headers = [
      {"Host", host},
      {"User-Agent", "Stealth-Trojan-Client/1.0"},
      {"Connection", "close"}
    ]

    all_headers = Keyword.merge(default_headers, headers)

    header_lines =
      Enum.map(all_headers, fn {key, value} ->
        "#{key}: #{value}\r\n"
      end)

    "#{method} #{path} HTTP/1.1\r\n" <>
      Enum.join(header_lines) <>
      "\r\n" <> body
  end

  defp proxy_direction(from_socket, to_socket, direction) do
    case read_socket(from_socket) do
      {:ok, data} when byte_size(data) > 0 ->
        case write_socket(to_socket, data) do
          :ok ->
            Logger.debug("Proxied #{byte_size(data)} bytes #{direction}")
            proxy_direction(from_socket, to_socket, direction)

          {:error, reason} ->
            Logger.debug("Write error #{direction}: #{inspect(reason)}")
            :error
        end

      {:ok, <<>>} ->
        proxy_direction(from_socket, to_socket, direction)

      {:error, :closed} ->
        Logger.debug("Connection closed #{direction}")
        :closed

      {:error, reason} ->
        Logger.debug("Read error #{direction}: #{inspect(reason)}")
        :error
    end
  end

  defp read_socket(socket) do
    case socket do
      %ThousandIsland.Socket{} ->
        ThousandIsland.Socket.recv(socket, 0, 30_000)

      _ ->
        # Try SSL socket first, then TCP
        case :ssl.recv(socket, 0, 30_000) do
          {:error, :closed} -> {:error, :closed}
          {:error, _} -> :gen_tcp.recv(socket, 0, 30_000)
          result -> result
        end
    end
  end

  defp write_socket(socket, data) do
    case socket do
      %ThousandIsland.Socket{} ->
        ThousandIsland.Socket.send(socket, data)

      _ ->
        # Try SSL socket first, then TCP
        case :ssl.send(socket, data) do
          :ok -> :ok
          {:error, _} -> :gen_tcp.send(socket, data)
        end
    end
  end
end
