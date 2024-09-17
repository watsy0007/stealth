defmodule Stealth.Protocols.Shadowsocks.Protocol do
  def split_iv(data, iv_size) do
    with <<iv::bytes-size(iv_size), payload::bytes>> <- data do
      {:ok, iv, payload}
    else
      _ -> {:error, :invalid_request}
    end
  end

  @doc """
  https://github.com/shadowsocks/shadowsocks-org/wiki/Protocol#addressing
  [1-byte type][variable-length host][2-byte port]
  """
  def parse_shadowsocks_request(data) do
    case data do
      # IP4
      <<1, addr::bytes-4, port::16, payload::bytes>> ->
        {:ok, %{req_type: :ip4, addr: addr, port: port, payload: payload}}

      # host
      <<3, len, addr::bytes-size(len), port::16, payload::bytes>> ->
        {:ok, %{req_type: :host, addr: addr, port: port, payload: payload}}

      # IP6
      <<4, addr::bytes-16, port::16, payload::bytes>> ->
        {:ok, %{req_type: :ip6, addr: addr, port: port, payload: payload}}

      _ ->
        {:error, :invalid_request}
    end
  end
end
