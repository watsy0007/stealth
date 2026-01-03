defmodule MockHTTPServer do
  @moduledoc """
  A simple mock HTTP server for testing purposes.
  Responds to HTTP requests with basic responses.
  """

  use GenServer
  require Logger

  @default_port 18080

  def start_link(opts \\ []) do
    port = Keyword.get(opts, :port, @default_port)
    GenServer.start_link(__MODULE__, port, name: __MODULE__)
  end

  def stop do
    GenServer.stop(__MODULE__)
  end

  def get_port do
    GenServer.call(__MODULE__, :get_port)
  end

  @impl true
  def init(port) do
    listen_opts = [
      :binary,
      active: false,
      reuseaddr: true,
      packet: 0
    ]

    case :gen_tcp.listen(port, listen_opts) do
      {:ok, listen_socket} ->
        Logger.debug("Mock HTTP server started on port #{port}")
        send(self(), :accept)
        {:ok, %{listen_socket: listen_socket, port: port, clients: []}}

      {:error, reason} ->
        Logger.error("Failed to start mock HTTP server: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  @impl true
  def handle_info(:accept, %{listen_socket: listen_socket} = state) do
    case :gen_tcp.accept(listen_socket, 100) do
      {:ok, client_socket} ->
        # Spawn a process to handle the client
        spawn(fn -> handle_client(client_socket) end)
        send(self(), :accept)
        {:noreply, state}

      {:error, :timeout} ->
        # No connection yet, keep accepting
        send(self(), :accept)
        {:noreply, state}

      {:error, reason} ->
        Logger.error("Accept error: #{inspect(reason)}")
        send(self(), :accept)
        {:noreply, state}
    end
  end

  @impl true
  def handle_call(:get_port, _from, %{port: port} = state) do
    {:reply, port, state}
  end

  @impl true
  def terminate(_reason, %{listen_socket: listen_socket}) do
    :gen_tcp.close(listen_socket)
    :ok
  end

  defp handle_client(socket) do
    case :gen_tcp.recv(socket, 0, 5000) do
      {:ok, data} ->
        Logger.debug("Mock server received: #{byte_size(data)} bytes")

        # Parse the request to determine the type
        response = build_response(data)
        :gen_tcp.send(socket, response)

        # Keep connection alive for a bit to allow reading response
        :timer.sleep(50)
        :gen_tcp.close(socket)

      {:error, reason} ->
        Logger.debug("Client read error: #{inspect(reason)}")
        :gen_tcp.close(socket)
    end
  end

  defp build_response(data) do
    cond do
      String.contains?(data, "POST ") ->
        # POST request
        body = ~s({"status": "ok", "message": "POST received"})
        """
        HTTP/1.1 200 OK\r
        Content-Type: application/json\r
        Content-Length: #{byte_size(body)}\r
        Connection: close\r
        \r
        #{body}
        """

      String.contains?(data, "GET ") ->
        # GET request
        body = ~s({"status": "ok", "message": "Mock HTTP Server"})
        """
        HTTP/1.1 200 OK\r
        Content-Type: application/json\r
        Content-Length: #{byte_size(body)}\r
        Connection: close\r
        \r
        #{body}
        """

      true ->
        # Unknown request
        body = "Bad Request"
        """
        HTTP/1.1 400 Bad Request\r
        Content-Type: text/plain\r
        Content-Length: #{byte_size(body)}\r
        Connection: close\r
        \r
        #{body}
        """
    end
  end
end
