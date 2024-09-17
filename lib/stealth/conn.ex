defmodule Stealth.Conn do
  require Logger

  alias Stealth.DNSCache

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

  def resolve_remote_address(%{req_type: :host, addr: addr} = req) do
    case DNSCache.fetch(addr) do
      {:ok, ip} ->
        {:ok, req |> Map.put(:ip, ip)}

      {status, reason} when status in [:ignore, :error] ->
        {:error, reason}
    end
  end

  def resolve_remote_address(%{req_type: :ip4, addr: addr} = req) do
    ip =
      addr
      |> :binary.bin_to_list()
      |> List.to_tuple()

    {:ok, req |> Map.put(:ip, ip)}
  end

  def resolve_remote_address(%{req_type: :ip6, addr: addr} = req) do
    ip =
      for <<group::16 <- addr>> do
        group
      end
      # { x, x, x, x, x, x, x, x } representation
      |> List.to_tuple()
      # ::xx:xx:xx representation, :gen_tcp.connect only takes this one
      |> :inet.ntoa()

    {:ok, req |> Map.put(:ip, ip)}
  end

  def resolve_remote_address(_), do: {:error, :invalid_request}

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

  def tcp_send_request(%{remote: r, payload: payload} = req) when byte_size(payload) > 0 do
    case :gen_tcp.send(r, payload) do
      :ok -> {:ok, req}
      {:error, _} -> {:error, :invalid_conn}
    end
  end

  def tcp_send_request(%{payload: payload} = req) when byte_size(payload) == 0, do: {:ok, req}
  def tcp_send_request(_), do: {:error, :invalid_conn}

  def tcp_connect_remote(req), do: tcp_connect_remote(req, @socket_option, @tcp_retry)

  def tcp_connect_remote(%{ip: r, port: port} = req, opts, retry) when retry > 1 do
    case :gen_tcp.connect(r, port, opts) do
      {:ok, client} ->
        {:ok, req |> Map.put(:remote, client)}

      {:error, _} ->
        Logger.debug("retrying! #{inspect(r)}:#{port}")
        :timer.sleep(10)
        tcp_connect_remote(req, port, opts, retry - 1)
    end
  end

  def tcp_connect_remote(%{ip: r, port: port} = req, port, opts, 1) do
    case :gen_tcp.connect(r, port, opts) do
      {:ok, client} ->
        {:ok, req |> Map.put(:remote, client)}

      {:error, reason} ->
        Logger.debug("Error connecting to #{inspect(req.addr)}:#{port} :: #{reason}")
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
