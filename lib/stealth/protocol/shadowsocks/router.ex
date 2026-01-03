defmodule Stealth.Protocol.Shadowsocks.Router do
  @moduledoc """
  HTTP router for Shadowsocks WebSocket endpoint.
  Handles WebSocket upgrade requests on /shadowsocks and /ss paths.
  """

  use Plug.Router

  plug(:match)
  plug(:dispatch)

  def init(opts), do: opts

  get "/shadowsocks" do
    handle_ws_upgrade(conn, opts)
  end

  get "/ss" do
    handle_ws_upgrade(conn, opts)
  end

  match _ do
    send_resp(conn, 404, "Not Found")
  end

  defp handle_ws_upgrade(conn, opts) do
    cipher = Keyword.fetch!(opts, :cipher)

    WebSockAdapter.upgrade(
      conn,
      Stealth.Protocol.Shadowsocks.WSHandler,
      [cipher: cipher],
      []
    )
  end
end
