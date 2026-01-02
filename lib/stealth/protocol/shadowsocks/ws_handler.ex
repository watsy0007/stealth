defmodule Stealth.Protocol.Shadowsocks.WSHandler do
  @moduledoc """
  WebSocket handler for Shadowsocks protocol.
  Implements WebSock behavior to handle WebSocket connections with Shadowsocks encryption.
  """

  require Logger
  alias Stealth.Protocol.Shadowsocks.{Cipher, Protocol}
  alias Stealth.Conn

  @behaviour WebSock

  defstruct [
    :cipher,
    :remote,
    :state
  ]

  @impl WebSock
  def init(opts) do
    cipher = Keyword.fetch!(opts, :cipher)

    Logger.debug("WebSocket connection initialized for Shadowsocks")

    state = %__MODULE__{
      cipher: cipher,
      remote: nil,
      state: :initial
    }

    {:ok, state}
  end

  @impl WebSock
  def handle_in({data, opcode: :binary}, %{state: :initial} = state) do
    # First message: should contain IV + initial request
    case process_initial_handshake(data, state) do
      {:ok, new_state, iv_response} ->
        {:push, {:binary, iv_response}, %{new_state | state: :connected}}

      {:error, reason} ->
        Logger.error("Initial handshake failed: #{inspect(reason)}")
        {:stop, :normal, state}
    end
  end

  @impl WebSock
  def handle_in({data, opcode: :binary}, %{state: :connected} = state) do
    # Subsequent messages: encrypted proxy data
    case process_client_data(data, state) do
      {:ok, new_state} ->
        {:ok, new_state}

      {:error, reason} ->
        Logger.error("Error processing client data: #{inspect(reason)}")
        {:stop, :normal, state}
    end
  end

  @impl WebSock
  def handle_in(_other, state) do
    # Ignore non-binary frames (text, ping, pong, etc.)
    {:ok, state}
  end

  @impl WebSock
  def handle_info({:tcp, remote, data}, %{remote: remote} = state) do
    # Data from remote server, encrypt and send to client
    case encrypt_and_send(data, state) do
      {:ok, new_state, encrypted} ->
        :inet.setopts(remote, active: :once)
        {:push, {:binary, encrypted}, new_state}

      {:error, reason} ->
        Logger.error("Error encrypting data: #{inspect(reason)}")
        {:stop, :normal, state}
    end
  end

  @impl WebSock
  def handle_info({:tcp_closed, remote}, %{remote: remote} = state) do
    Logger.debug("Remote connection closed")
    {:stop, :normal, state}
  end

  @impl WebSock
  def handle_info({:tcp_error, remote, reason}, %{remote: remote} = state) do
    Logger.error("Remote TCP error: #{inspect(reason)}")
    {:stop, :normal, state}
  end

  @impl WebSock
  def handle_info(_other, state) do
    # Ignore unknown messages
    {:ok, state}
  end

  @impl WebSock
  def terminate(reason, state) do
    Logger.debug("WebSocket connection terminated: #{inspect(reason)}")

    if state.remote do
      :gen_tcp.close(state.remote)
    end

    :ok
  end

  # Private functions

  defp process_initial_handshake(data, %{cipher: cipher} = state) do
    iv_len = cipher.iv_len

    with {:ok, iv, payload} <- Protocol.split_iv(data, iv_len),
         {:ok, cipher} <- Cipher.init_decoder(cipher, iv),
         {:ok, cipher, decrypted} <- Cipher.stream_decode(cipher, payload),
         {:ok, req} <- Conn.parse_socks5_request(decrypted),
         {:ok, req} <- Conn.resolve_remote_address(req),
         {:ok, req} <- Conn.filter_forbidden_addresses(req),
         {:ok, req} <- Conn.tcp_connect_remote(req),
         {:ok, req} <- Conn.tcp_send_request(req) do
      # Initialize encoder and generate IV to send to client
      {:ok, cipher, iv_send} = Cipher.init_encoder(cipher)

      # Set remote socket to active mode to receive messages
      :inet.setopts(req.remote, active: :once)

      new_state = %{
        state
        | cipher: cipher,
          remote: req.remote
      }

      {:ok, new_state, iv_send}
    end
  end

  defp process_client_data(data, %{cipher: cipher, remote: remote} = state) do
    with {:ok, cipher, decrypted} <- Cipher.stream_decode(cipher, data),
         :ok <- :gen_tcp.send(remote, decrypted) do
      {:ok, %{state | cipher: cipher}}
    end
  end

  defp encrypt_and_send(data, %{cipher: cipher} = state) do
    with {:ok, cipher, encrypted} <- Cipher.stream_encode(cipher, data) do
      {:ok, %{state | cipher: cipher}, encrypted}
    end
  end
end
