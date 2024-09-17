defmodule Stealth.Protocols.Shadowsocks.Worker do
  require Logger
  alias Stealth.Protocols.Shadowsocks.Protocol
  alias Stealth.Cipher
  alias Stealth.Conn

  def accept(port, cipher) do
    {:ok, socket} =
      :gen_tcp.listen(port, [
        :binary,
        packet: :raw,
        nodelay: true,
        keepalive: true,
        active: true,
        reuseaddr: true
      ])

    Logger.debug("Accepting connections on port #{port}\n")

    loop_acceptor(socket, cipher)
  end

  defp loop_acceptor(socket, cipher) do
    {:ok, local} = :gen_tcp.accept(socket)

    Logger.debug("Accepted connection from #{inspect(local)}\n")

    {:ok, pid} =
      Task.Supervisor.start_child(Stealth.TaskSupervisor, fn ->
        serve(%{local: local, remote: nil}, cipher)
      end)

    :ok = :gen_tcp.controlling_process(local, pid)
    loop_acceptor(socket, cipher)
  end

  defp serve(%{local: l} = state, cipher) do
    {:ok, c, iv} = Cipher.init_encoder(cipher)
    :gen_tcp.send(l, iv)
    serve_loop(state, c)
  end

  defp read_line(%{local: l, remote: r} = state, cipher) do
    receive do
      {:tcp, ^l, data} ->
        process_client_socket(state, data, cipher)

      {:tcp, ^r, data} ->
        process_remote_socket(state, data, cipher)

      {:tcp_closed, ^l} ->
        Logger.debug("Client #{inspect(l)} closed connection\n")
        :gen_tcp.close(r)
        Process.exit(self(), :local_closed)
        {state, cipher}

      {:tcp_closed, ^r} ->
        Logger.debug("Remote closed connection\n")
        {state, cipher}

      other ->
        Logger.warning("Unknown message: #{inspect(other)}\n")
        {state, cipher}
    end
  end

  defp process_client_socket(state, data, %{decoder: nil, iv_len: iv_len} = cipher) do
    with {:ok, iv, payload} = Protocol.split_iv(data, iv_len),
         {:ok, cipher} = Cipher.init_decoder(cipher, iv),
         {:ok, cipher, data} = Cipher.stream_decode(cipher, payload),
         {:ok, req} <- Protocol.parse_shadowsocks_request(data),
         {:ok, req} <- Conn.resolve_remote_address(req),
         {:ok, req} <- Conn.filter_forbidden_addresses(req),
         {:ok, req} = Conn.tcp_connect_remote(req),
         {:ok, req} = Conn.tcp_send_request(req) do
      {%{state | remote: req.remote}, cipher}
    end
  end

  defp process_client_socket(%{local: l, remote: r} = state, data, cipher) do
    :inet.setopts(l, active: :once)
    {:ok, cipher, data} = Cipher.stream_decode(cipher, data)
    Logger.debug("Received client data: #{inspect(data)}\n")
    :gen_tcp.send(r, data)
    {state, cipher}
  end

  defp process_remote_socket(%{local: l, remote: r} = state, data, cipher) do
    :inet.setopts(r, active: :once)
    Logger.debug("Received remote data: #{inspect(data)}\n")
    {:ok, cipher, data} = Cipher.stream_encode(cipher, data)
    :gen_tcp.send(l, data)
    {state, cipher}
  end

  defp serve_loop(socket, cipher) do
    {socket, cipher} = socket |> read_line(cipher)
    serve_loop(socket, cipher)
  end
end
