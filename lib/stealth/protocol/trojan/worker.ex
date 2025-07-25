defmodule Stealth.Protocol.Trojan.Worker do
  use ThousandIsland.Handler
  alias Stealth.Protocol.Trojan.Protocol
  require Logger
  alias Stealth.Conn

  @impl ThousandIsland.Handler
  def handle_data(_data, _socket, state) do
    # 在正常代理模式下，数据会直接转发
    {:continue, state}
  end

  @impl ThousandIsland.Handler
  def handle_connection(client_socket, state) do
    passwd = :proplists.get_value(:passwd, state, "") |> Protocol.sha224_hash()
    server = :proplists.get_value(:server, state, host: "example.com", port: 443)

    case Protocol.parse_request(client_socket, passwd) do
      {:ok, req} ->
        Logger.info("Valid Trojan request to #{inspect(req)}")
        proxy_connection(client_socket, req)

      {:error, :invalid_protocol} ->
        Logger.info("Invalid protocol, forwarding to default server")

        proxy_connection(client_socket, %{
          req_type: :host,
          addr: server[:host],
          port: server[:port],
          payload: <<>>
        })

      {:error, reason} ->
        Logger.error("Connection error: #{inspect(reason)}")
        {:close, state}
    end
  end

  defp proxy_connection(client_socket, req) do
    with {:ok, req} <- Conn.resolve_remote_address(req),
         {:ok, req} <- Conn.filter_forbidden_addresses(req),
         {:ok, %{remote: target_socket}} = Conn.tcp_connect_remote(req) do
      start_bidirectional_proxy(client_socket, target_socket)
    end
  end

  defp start_bidirectional_proxy(client_socket, target_socket) do
    task1 =
      Task.async(fn ->
        proxy_data(client_socket, target_socket, "client->target")
      end)

    task2 =
      Task.async(fn ->
        proxy_data(target_socket, client_socket, "target->client")
      end)

    case Task.yield_many([task1, task2], :infinity) do
      {:ok, term} ->
        Logger.info("Proxy connection successful: #{inspect(term)}")
        Task.shutdown(task1, :brutal_kill)
        Task.shutdown(task2, :brutal_kill)

      {:exit, reason} ->
        # 至少一个Task完成
        Logger.info("Proxy connection closed: #{inspect(reason)}")
        Task.shutdown(task1, :brutal_kill)
        Task.shutdown(task2, :brutal_kill)

      nil ->
        # 超时情况
        Logger.info("Proxy connection timeout")
        Task.shutdown(task1, :brutal_kill)
        Task.shutdown(task2, :brutal_kill)
    end

    cleanup_sockets(client_socket, target_socket)

    {:close, nil}
  end

  defp cleanup_sockets(client_socket, target_socket) do
    :gen_tcp.close(client_socket)
    :gen_tcp.close(target_socket)
  end

  defp proxy_data(from_socket, to_socket, direction) do
    case read_socket_data(from_socket) do
      {:ok, data} when byte_size(data) > 0 ->
        case write_socket_data(to_socket, data) do
          :ok ->
            Logger.debug("Proxied #{byte_size(data)} bytes #{direction}")
            proxy_data(from_socket, to_socket, direction)

          {:error, reason} ->
            Logger.debug("Write error #{direction}: #{inspect(reason)}")
            exit(:write_error)
        end

      {:ok, <<>>} ->
        # 空数据，继续读取
        proxy_data(from_socket, to_socket, direction)

      {:error, :closed} ->
        Logger.debug("Connection closed #{direction}")
        exit(:connection_closed)

      {:error, reason} ->
        Logger.debug("Read error #{direction}: #{inspect(reason)}")
        exit(:read_error)
    end
  end

  defp read_socket_data(socket) do
    case socket do
      %ThousandIsland.Socket{} ->
        ThousandIsland.Socket.recv(socket, 0, 30_000)

      _ ->
        :gen_tcp.recv(socket, 0, 30_000)
    end
  end

  defp write_socket_data(socket, data) do
    case socket do
      %ThousandIsland.Socket{} ->
        ThousandIsland.Socket.send(socket, data)

      _ ->
        :gen_tcp.send(socket, data)
    end
  end
end
