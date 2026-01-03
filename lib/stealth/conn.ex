defmodule Stealth.Conn do
  @moduledoc """
  Connection utilities and SOCKS5 protocol handling.

  Provides functions for parsing and building SOCKS5 requests,
  DNS resolution, and TCP connection management.
  """

  require Logger

  alias Stealth.DNSCache

  # SOCKS5 command types
  @cmd_connect 0x01
  @cmd_bind 0x02
  @cmd_udp_associate 0x03

  # SOCKS5 address types
  @atyp_ipv4 0x01
  @atyp_domain 0x03
  @atyp_ipv6 0x04

  @socket_option [
    :binary,
    active: :once,
    nodelay: true,
    keepalive: true,
    packet: 0,
    sndbuf: 2_097_152,
    recbuf: 2_097_152,
    reuseaddr: true
  ]

  # how many times will each remote be tried?
  @tcp_retry 2

  @doc """
  Parse SOCKS5 request from binary data.

  Supports two formats:
  - Standard SOCKS5: ATYP + ADDRESS + PORT + PAYLOAD
  - CMD-prefixed: CMD + ATYP + ADDRESS + PORT + PAYLOAD

  Returns a map with request type, address, port, and optional CMD.

  ## Examples

      iex> Conn.parse_socks5_request(<<1, 127, 0, 0, 1, 0, 80, "payload">>)
      {:ok, %{req_type: :ipv4, addr: <<127, 0, 0, 1>>, port: 80, payload: "payload"}}

      iex> Conn.parse_socks5_request(<<1, 1, 127, 0, 0, 1, 0, 80, "payload">>)
      {:ok, %{cmd: :connect, req_type: :ipv4, addr: <<127, 0, 0, 1>>, port: 80, payload: "payload"}}
  """
  def parse_socks5_request(data) when byte_size(data) >= 2 do
    <<first, second, _rest::binary>> = data

    # Auto-detect format: If first byte is valid CMD (1/2/3) and second is valid ATYP (1/3/4),
    # assume CMD-prefixed format. Otherwise, assume standard SOCKS5 format.
    if first in [@cmd_connect, @cmd_bind, @cmd_udp_associate] and
         second in [@atyp_ipv4, @atyp_domain, @atyp_ipv6] do
      with {:ok, result} <- do_parse_socks5(data, 1) do
        {:ok, Map.put(result, :cmd, byte_to_command(first))}
      end
    else
      do_parse_socks5(data, 0)
    end
  end

  def parse_socks5_request(data), do: do_parse_socks5(data, 0)

  # Unified SOCKS5 parsing with configurable offset for optional CMD byte
  defp do_parse_socks5(data, offset) do
    case data do
      # IPv4: ATYP(1) + 4 bytes + port(2) + payload
      <<_::binary-size(offset), @atyp_ipv4, a, b, c, d, port::16, payload::binary>> ->
        {:ok, %{req_type: :ipv4, addr: <<a, b, c, d>>, port: port, payload: payload}}

      # Domain: ATYP(3) + length(1) + domain + port(2) + payload
      <<_::binary-size(offset), @atyp_domain, len, addr::binary-size(len), port::16,
        payload::binary>> ->
        {:ok, %{req_type: :host, addr: addr, port: port, payload: payload}}

      # IPv6: ATYP(4) + 16 bytes + port(2) + payload
      <<_::binary-size(offset), @atyp_ipv6, addr::binary-size(16), port::16, payload::binary>> ->
        {:ok, %{req_type: :ipv6, addr: addr, port: port, payload: payload}}

      _ ->
        {:error, :invalid_request}
    end
  end

  @doc """
  Build SOCKS5 address format from address and port.

  ## Parameters
    - address: IP tuple {a, b, c, d}, IPv6 tuple, domain string, or address map
    - port: Port number
    - cmd: Command type (:connect, :bind, :udp_associate), default :connect

  ## Examples

      iex> Conn.build_socks5_address({192, 168, 1, 1}, 80)
      {:ok, <<1, 1, 192, 168, 1, 1, 0, 80>>}

      iex> Conn.build_socks5_address("example.com", 443)
      {:ok, <<1, 3, 11, "example.com", 1, 187>>}
  """
  def build_socks5_address(address, port, cmd \\ :connect)

  # IPv4 address
  def build_socks5_address({a, b, c, d}, port, cmd)
      when is_integer(a) and is_integer(b) and is_integer(c) and is_integer(d) and
             is_integer(port) and port >= 0 and port <= 65535 do
    cmd_byte = command_to_byte(cmd)
    {:ok, <<cmd_byte, @atyp_ipv4, a, b, c, d, port::16>>}
  end

  # IPv6 address
  def build_socks5_address({a, b, c, d, e, f, g, h}, port, cmd)
      when is_integer(port) and port >= 0 and port <= 65535 do
    cmd_byte = command_to_byte(cmd)

    {:ok,
     <<cmd_byte, @atyp_ipv6, a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16, port::16>>}
  end

  # Domain name
  def build_socks5_address(domain, port, cmd)
      when is_binary(domain) and is_integer(port) and port >= 0 and port <= 65535 do
    domain_len = byte_size(domain)

    if domain_len > 255 do
      {:error, :domain_too_long}
    else
      cmd_byte = command_to_byte(cmd)
      {:ok, <<cmd_byte, @atyp_domain, domain_len, domain::binary, port::16>>}
    end
  end

  # Address map (from parsed request)
  def build_socks5_address(%{req_type: :ipv4, ip: ip, port: port}, _port_override, cmd) do
    build_socks5_address(ip, port, cmd)
  end

  def build_socks5_address(%{req_type: :ipv6, ip: ip, port: port}, _port_override, cmd) do
    build_socks5_address(ip, port, cmd)
  end

  def build_socks5_address(%{req_type: :host, addr: addr, port: port}, _port_override, cmd) do
    build_socks5_address(addr, port, cmd)
  end

  def build_socks5_address(_, _, _), do: {:error, :invalid_address}

  @doc """
  Convert command name to SOCKS5 command byte.
  """
  def command_to_byte(:connect), do: @cmd_connect
  def command_to_byte(:bind), do: @cmd_bind
  def command_to_byte(:udp_associate), do: @cmd_udp_associate
  def command_to_byte(_), do: nil

  @doc """
  Convert SOCKS5 command byte to command name.
  """
  def byte_to_command(@cmd_connect), do: :connect
  def byte_to_command(@cmd_bind), do: :bind
  def byte_to_command(@cmd_udp_associate), do: :udp_associate
  def byte_to_command(_), do: :unknown

  @doc """
  Resolve address to IP tuple for connection.

  - :host type: Perform DNS lookup via cache
  - :ipv4 type: Convert 4-byte binary to tuple
  - :ipv6 type: Convert 16-byte binary to tuple
  """
  def resolve_remote_address(%{req_type: :host, addr: addr} = req) do
    case DNSCache.fetch(addr) do
      {:ok, ip} -> {:ok, Map.put(req, :ip, ip)}
      {status, reason} when status in [:ignore, :error] -> {:error, reason}
    end
  end

  def resolve_remote_address(%{req_type: :ipv4, addr: addr} = req) do
    ip = addr |> :binary.bin_to_list() |> List.to_tuple()
    {:ok, Map.put(req, :ip, ip)}
  end

  def resolve_remote_address(%{req_type: :ipv6, addr: addr} = req) do
    ip =
      for(<<group::16 <- addr>>, do: group)
      |> List.to_tuple()
      |> :inet.ntoa()

    {:ok, Map.put(req, :ip, ip)}
  end

  def resolve_remote_address(_), do: {:error, :invalid_request}

  @doc """
  Filter forbidden addresses in production environment.

  Blocks private IP ranges:
  - 192.168.x.x, 10.x.x.x, 172.16-31.x.x (RFC 1918)
  - 127.0.0.x (loopback)
  - 0.x.x.x (invalid)

  In dev/test mode, all addresses are allowed.
  """
  if Mix.env() == :prod do
    def filter_forbidden_addresses(%{ip: ip} = req) do
      case ip do
        {192, 168, _, _} -> {:error, :private_address}
        {10, _, _, _} -> {:error, :private_address}
        {127, 0, 0, _} -> {:error, :private_address}
        {0, _, _, _} -> {:error, :private_address}
        {172, x, _, _} when x in 16..31 -> {:error, :private_address}
        _ -> {:ok, req}
      end
    end
  else
    def filter_forbidden_addresses(req), do: {:ok, req}
  end

  @doc """
  Send initial payload to remote server if present.
  """
  def tcp_send_request(%{remote: remote, payload: payload} = req)
      when byte_size(payload) > 0 do
    case :gen_tcp.send(remote, payload) do
      :ok -> {:ok, req}
      {:error, _reason} -> {:error, :invalid_conn}
    end
  end

  def tcp_send_request(%{payload: payload} = req) when byte_size(payload) == 0, do: {:ok, req}
  def tcp_send_request(_), do: {:error, :invalid_conn}

  @doc """
  Connect to remote server with retry logic.
  """

  def tcp_connect_remote(req), do: tcp_connect_remote(req, @socket_option, @tcp_retry)

  def tcp_connect_remote(%{ip: ip, port: port} = req, opts, retry) when retry > 1 do
    case :gen_tcp.connect(ip, port, opts) do
      {:ok, client} ->
        {:ok, Map.put(req, :remote, client)}

      {:error, _reason} ->
        Logger.debug("Retrying connection to #{inspect(ip)}:#{port}")
        :timer.sleep(10)
        tcp_connect_remote(req, opts, retry - 1)
    end
  end

  def tcp_connect_remote(%{ip: ip, port: port} = req, opts, 1) do
    case :gen_tcp.connect(ip, port, opts) do
      {:ok, client} ->
        {:ok, Map.put(req, :remote, client)}

      {:error, reason} ->
        Logger.debug("Failed to connect to #{inspect(req.addr)}:#{port} - #{reason}")
        {:error, reason}
    end
  end

  def port_ip(port) do
    case :inet.peername(port) do
      {:ok, {ip, _}} -> ip
      {:error, _} -> nil
    end
  end
end
