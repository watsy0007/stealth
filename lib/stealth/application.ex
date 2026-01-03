defmodule Stealth.Application do
  use Application
  require Logger
  alias Stealth.Protocol.Shadowsocks
  alias Stealth.Protocol.Trojan

  def start(_, _) do
    children = [
      Stealth.DNSCache,
      {Task.Supervisor, name: Stealth.TaskSupervisor}
    ]

    ss =
      if(Application.get_env(:stealth, :enable_ss)) do
        opts = Application.get_env(:stealth, :ss)

        # TCP worker
        tcp_worker =
          {Task, fn -> Shadowsocks.Worker.start(opts[:port], opts[:method], opts[:passwd]) end}

        # WebSocket server (if enabled)
        ws_server =
          if opts[:ws_enabled] do
            {:ok, cipher} = Shadowsocks.Cipher.setup(opts[:method], opts[:passwd])

            {Bandit, port: opts[:ws_port], plug: {Shadowsocks.Router, cipher: cipher}}
          else
            nil
          end

        [tcp_worker, ws_server] |> Enum.reject(&is_nil/1)
      else
        []
      end

    trojan =
      if Application.get_env(:stealth, :enable_trojan) do
        opts = Application.get_env(:stealth, :trojan)
        certfile = Keyword.pop(opts, :certfile)
        keyfile = Keyword.pop(opts, :keyfile)

        ssl_opts = [
          certfile: certfile,
          keyfile: keyfile
        ]

        server_opts = [
          port: opts[:port],
          transport_module: ThousandIsland.Transports.SSL,
          transport_options: ssl_opts,
          handler_module: Trojan.Worker,
          handler_options: [
            passwd: Trojan.Protocol.sha224_hash(opts[:passwd]),
            server: opts[:server]
          ],
          num_acceptors: 10,
          max_connections: 1000
        ]

        [
          {ThousandIsland, server_opts}
        ]
      else
        []
      end

    modules = ss ++ trojan

    Logger.info("Starting [ #{node()} ] node VERSION #{Application.spec(:stealth, :vsn)}\n")
    Logger.info("Enabled modules: #{inspect(children)}\n")

    Supervisor.start_link(children ++ modules, strategy: :one_for_one, name: Stealth)
  end
end
