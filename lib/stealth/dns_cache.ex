defmodule Stealth.DNSCache do
  require Logger
  import Cachex.Spec

  @ttl :timer.seconds(120)
  def child_spec(_) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [nil]}}
  end

  def start_link(_) do
    Cachex.start_link(__MODULE__, expiration: expiration(default: @ttl))
  end

  def fetch(addr) do
    case Cachex.get(__MODULE__, addr) do
      {:ok, ip} when ip !== nil -> {:ok, ip}
      _ -> fetch_internal(addr)
    end
  end

  defp fetch_internal(addr) do
    addr_cl = to_charlist(addr)

    Logger.debug("dnscache internal -> #{inspect(addr_cl)}")

    case :inet.getaddr(addr_cl, :inet) do
      {:ok, ip} ->
        Cachex.put(__MODULE__, addr, ip)
        {:ok, ip}

      _ ->
        {:ignore, {:nxdomain, addr}}
    end
  end
end
