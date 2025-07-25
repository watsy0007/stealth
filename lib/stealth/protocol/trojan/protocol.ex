defmodule Stealth.Protocol.Trojan.Protocol do
  require Logger
  alias Stealth.Conn
  @crlf "\r\n"

  def sha224_hash(passwd) do
    :crypto.hash(:sha224, passwd)
    |> Base.encode16(case: :lower)
  end

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
