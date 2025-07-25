defmodule Stealth.Protocol.Shadowsocks.Protocol do
  def split_iv(data, iv_size) do
    with <<iv::bytes-size(iv_size), payload::bytes>> <- data do
      {:ok, iv, payload}
    else
      _ -> {:error, :invalid_request}
    end
  end
end
