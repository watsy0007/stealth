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
         {:ok, %{remote: target_socket}} <- Conn.tcp_connect_remote(req) do
      start_bidirectional_proxy(client_socket, target_socket)
    else
      {:error, reason} ->
        Logger.error("Proxy connection failed: #{inspect(reason)}")
        {:close, nil}
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

    # Task.yield_many returns a list of {task, result} tuples
    results = Task.yield_many([task1, task2], :infinity)

    # At least one task has finished (either normally or with exit)
    Logger.debug("Proxy tasks finished: #{inspect(results)}")
    Task.shutdown(task1, :brutal_kill)
    Task.shutdown(task2, :brutal_kill)

    cleanup_sockets(client_socket, target_socket)

    {:close, nil}
  end

  defp cleanup_sockets(client_socket, target_socket) do
    # Close client socket (ThousandIsland.Socket)
    case client_socket do
      %ThousandIsland.Socket{} ->
        ThousandIsland.Socket.close(client_socket)

      _ ->
        :gen_tcp.close(client_socket)
    end

    # Close target socket (regular gen_tcp socket)
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
            # Exit normally - connection errors are expected
            exit(:normal)
        end

      {:ok, <<>>} ->
        # 空数据，继续读取
        proxy_data(from_socket, to_socket, direction)

      {:error, :closed} ->
        Logger.debug("Connection closed #{direction}")
        # Exit normally - connection closed is expected
        exit(:normal)

      {:error, reason} ->
        Logger.debug("Read error #{direction}: #{inspect(reason)}")
        # Exit normally - read errors during proxy are expected
        exit(:normal)
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
