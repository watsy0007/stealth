defmodule Stealth.Application do
  use Application
  require Logger
  alias Stealth.Protocols.Shadowsocks.Worker
  alias Stealth.Cipher

  def start(_, _) do
    port = Application.get_env(:stealth, :ss_port)
    password = Application.get_env(:stealth, :ss_password)
    method = Application.get_env(:stealth, :ss_method)

    {:ok, cipher} = Cipher.setup(method, password)

    children = [
      Stealth.DNSCache,
      {Task.Supervisor, name: Stealth.TaskSupervisor},
      {Task, fn -> Worker.accept(port, cipher) end}
    ]

    Logger.info("Starting [ #{node()} ] node VERSION #{Application.spec(:stealth, :vsn)}\n")
    Logger.info("Enabled modules: #{inspect(children)}\n")

    Supervisor.start_link(children, strategy: :one_for_one, name: Stealth)
  end
end
