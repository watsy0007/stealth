defmodule Stealth.Protocol.Trojan.Protocol do
  @moduledoc """
  Trojan protocol implementation with SSL/TLS encryption.

  The Trojan protocol uses TLS as transport layer encryption and SHA-224 for password authentication.
  Protocol format: SHA-224(password) + CRLF + SOCKS5 address + payload

  This module delegates SOCKS5 address building to `Stealth.Conn` for code reuse.
  """

  require Logger
  alias Stealth.Conn

  @crlf "\r\n"

  @doc """
  Compute SHA-224 hash of password in lowercase hexadecimal format.

  ## Examples

      iex> Stealth.Protocol.Trojan.Protocol.sha224_hash("password")
      "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
  """
  def sha224_hash(passwd) do
    :crypto.hash(:sha224, passwd)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Parse Trojan request from socket.

  Reads and validates the password hash, then parses the SOCKS5 address.
  """
  def parse_request(socket, passwd) do
    with {:ok, data} <- read_initial_data(socket),
         {:ok, %{payload: payload} = req} <- parse_protocol(data, passwd) do
      if byte_size(payload) > 0 do
        Logger.debug("Found #{byte_size(payload)} bytes of initial payload")
      end

      {:ok, req}
    else
      error -> error
    end
  end

  @doc """
  Build a complete Trojan request packet.

  ## Parameters
    - password: Plain text password
    - address: Target address (IP tuple, domain string, or address map)
    - port: Target port
    - payload: Optional initial payload data
    - cmd: Command type (:connect or :udp_associate), default :connect

  ## Examples

      iex> Protocol.build_request("mypass", {192, 168, 1, 1}, 80)
      {:ok, <<...>>}

      iex> Protocol.build_request("mypass", "example.com", 443, "GET / HTTP/1.1\\r\\n")
      {:ok, <<...>>}
  """
  def build_request(password, address, port, payload \\ "", cmd \\ :connect) do
    with {:ok, hash} <- {:ok, sha224_hash(password)},
         {:ok, socks5_addr} <- build_socks5_address(address, port, cmd) do
      request = hash <> @crlf <> socks5_addr <> @crlf <> payload
      {:ok, request}
    end
  end

  @doc """
  Build SOCKS5 address format.

  Delegates to `Stealth.Conn.build_socks5_address/3` for code reuse.

  ## Parameters
    - address: IP tuple {a, b, c, d}, IPv6 tuple, domain string, or address map
    - port: Port number
    - cmd: Command type (:connect or :udp_associate)

  ## Examples

      iex> Protocol.build_socks5_address({192, 168, 1, 1}, 80)
      {:ok, <<1, 1, 192, 168, 1, 1, 0, 80>>}

      iex> Protocol.build_socks5_address("example.com", 443)
      {:ok, <<1, 3, 11, "example.com", 1, 187>>}
  """
  defdelegate build_socks5_address(address, port, cmd \\ :connect), to: Conn

  @doc """
  Validate password hash.

  ## Examples

      iex> hash = Protocol.sha224_hash("password")
      iex> Protocol.validate_password(hash, "password")
      true

      iex> Protocol.validate_password("invalid", "password")
      false
  """
  def validate_password(hash, password) do
    expected_hash = sha224_hash(password)
    hash == expected_hash
  end

  @doc """
  Extract password hash from request data.

  ## Examples

      iex> request = Protocol.sha224_hash("pass") <> "\\r\\n" <> "data"
      iex> Protocol.extract_password_hash(request)
      {:ok, hash, remaining_data}
  """
  def extract_password_hash(data) when byte_size(data) >= 58 do
    case data do
      <<hash::binary-size(56), @crlf, rest::binary>> ->
        {:ok, hash, rest}

      _ ->
        {:error, :invalid_format}
    end
  end

  def extract_password_hash(_), do: {:error, :insufficient_data}

  @doc """
  Get command name from command byte.

  Delegates to `Stealth.Conn.byte_to_command/1` for code reuse.
  """
  defdelegate command_name(byte), to: Conn, as: :byte_to_command

  @doc """
  Get command byte from command name.

  Delegates to `Stealth.Conn.command_to_byte/1` for code reuse.
  """
  defdelegate command_byte(name), to: Conn, as: :command_to_byte

  # Private functions

  defp read_initial_data(socket) do
    # 读取足够的数据来解析协议头
    # 最小长度：56(hash) + 2(CRLF) + 1(CMD) + 1(ATYP) + 1(addr_len) + 2(port) + 2(CRLF) = 65
    case ThousandIsland.Socket.recv(socket, 65, 5000) do
      {:ok, data} when byte_size(data) >= 65 ->
        {:ok, data}

      {:ok, data} ->
        # 如果数据不足，尝试读取更多
        case ThousandIsland.Socket.recv(socket, 100 - byte_size(data), 2000) do
          {:ok, more_data} -> {:ok, data <> more_data}
          error -> error
        end

      error ->
        error
    end
  end

  defp parse_protocol(data, passwd) do
    try do
      # 解析密码哈希
      case data do
        <<hash::binary-size(56), @crlf, rest::binary>> ->
          if hash == passwd do
            Conn.parse_socks5_request(rest)
          else
            Logger.debug("Invalid password hash")
            {:error, :invalid_protocol}
          end

        _ ->
          Logger.debug("Invalid protocol format")
          {:error, :invalid_protocol}
      end
    rescue
      _ -> {:error, :invalid_protocol}
    end
  end
end
