defmodule Stealth.Protocol.Trojan.WorkerTest do
  use ExUnit.Case
  doctest Stealth.Protocol.Trojan.Worker
  alias Stealth.Protocol.Trojan.CertHelper
  alias Stealth.Protocol.Trojan.Worker
  require Logger
  @port 8443
  setup_all do
    {:ok, cert_info} = CertHelper.setup_test_certificates()

    cfg = [
      port: @port,
      transport_module: ThousandIsland.Transports.SSL,
      transport_options: [
        certfile: cert_info.cert_file,
        keyfile: cert_info.key_file,
        # 测试环境不验证客户端证书
        verify: :verify_none
      ],
      handler_module: Worker,
      handler_options: [
        passwd: "test_password_123",
        # 默认转发目标
        server: [host: "httpbin.org", port: 80]
      ],
      num_acceptors: 5
    ]

    Logger.info("Starting Trojan worker test server on port #{cfg[:port]}...")

    case ThousandIsland.start_link(cfg) do
      {:ok, pid} ->
        Logger.info("Trojan worker test server started successfully.")
        {:ok, server_pid: pid, cert_info: cert_info}

      {:error, reason} ->
        Logger.error("Failed to start Trojan worker test server: #{inspect(reason)}")
        :skip
    end
  end

  test "ssl_connection", state do
    Logger.info("Testing SSL connection to Trojan worker...")

    case :ssl.connect(
           ~c"localhost",
           @port,
           [:binary, {:active, false}, {:verify, :verify_none}]
         ) do
      {:ok, ssl_socket} ->
        Logger.info("SSL connection established successfully.")
        test_data = "invalid trojan request"

        case :ssl.send(ssl_socket, test_data) do
          :ok ->
            Logger.info("Data sent successfully.")

          {:error, reason} ->
            Logger.error("Failed to send data: #{inspect(reason)}")
            assert false
        end

        :ssl.close(ssl_socket)
        assert true

      {:error, reason} ->
        Logger.error("Failed to establish SSL connection: #{inspect(reason)}")
        assert false
    end
  end
end
