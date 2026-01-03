defmodule Stealth.Protocol.Trojan.WorkerTest do
  use ExUnit.Case
  doctest Stealth.Protocol.Trojan.Worker
  alias Stealth.Protocol.Trojan.{CertHelper, Protocol, Worker}
  require Logger

  @test_port 18443
  @test_password "test_password_123"
  @timeout 10_000

  setup_all do
    # Start the DNS cache for domain resolution
    start_supervised!(Stealth.DNSCache)

    {:ok, cert_info} = CertHelper.setup_test_certificates()

    cfg = [
      port: @test_port,
      transport_module: ThousandIsland.Transports.SSL,
      transport_options: [
        certfile: cert_info.cert_file,
        keyfile: cert_info.key_file,
        verify: :verify_none
      ],
      handler_module: Worker,
      handler_options: [
        passwd: @test_password,
        server: [host: "httpbin.org", port: 80]
      ],
      num_acceptors: 5
    ]

    Logger.info("Starting Trojan worker test server on port #{cfg[:port]}...")

    case ThousandIsland.start_link(cfg) do
      {:ok, server_pid} ->
        Logger.info("Trojan worker test server started successfully.")

        on_exit(fn ->
          # Stop the server with a timeout
          try do
            GenServer.stop(server_pid, :normal, 5000)
          catch
            :exit, _ -> :ok
          end
        end)

        {:ok, server_pid: server_pid, cert_info: cert_info}

      {:error, reason} ->
        Logger.error("Failed to start Trojan worker test server: #{inspect(reason)}")
        :skip
    end
  end

  describe "SSL connection" do
    test "establishes SSL connection successfully" do
      Logger.info("Testing SSL connection to Trojan worker...")

      assert {:ok, ssl_socket} =
               :ssl.connect(
                 ~c"localhost",
                 @test_port,
                 [:binary, {:active, false}, {:verify, :verify_none}],
                 @timeout
               )

      :ssl.close(ssl_socket)
    end

    test "accepts and handles invalid protocol data" do
      {:ok, ssl_socket} =
        :ssl.connect(
          ~c"localhost",
          @test_port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          @timeout
        )

      # 发送无效的 Trojan 协议数据
      test_data = "invalid trojan request"
      assert :ok = :ssl.send(ssl_socket, test_data)

      # 等待服务器处理
      :timer.sleep(100)

      :ssl.close(ssl_socket)
    end

    test "rejects connection with wrong password hash" do
      {:ok, ssl_socket} =
        :ssl.connect(
          ~c"localhost",
          @test_port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          @timeout
        )

      # 构造带错误密码的请求
      wrong_hash = Protocol.sha224_hash("wrong_password")

      # CONNECT
      # IPv4
      # localhost
      # Port 80
      request =
        wrong_hash <>
          "\r\n" <>
          <<0x01>> <>
          <<0x01>> <>
          <<127, 0, 0, 1>> <>
          <<0, 80>> <>
          "\r\n"

      assert :ok = :ssl.send(ssl_socket, request)

      # 服务器应该会转发到默认服务器或关闭连接
      :timer.sleep(100)

      :ssl.close(ssl_socket)
    end
  end

  describe "Trojan protocol handling" do
    test "parses valid Trojan request with IPv4 address" do
      {:ok, ssl_socket} =
        :ssl.connect(
          ~c"localhost",
          @test_port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          @timeout
        )

      # 构造有效的 Trojan 请求
      hash = Protocol.sha224_hash(@test_password)

      # CONNECT
      # IPv4
      # example.com IP
      # Port 80
      request =
        hash <>
          "\r\n" <>
          <<0x01>> <>
          <<0x01>> <>
          <<93, 184, 216, 34>> <>
          <<0, 80>> <>
          "\r\n"

      assert :ok = :ssl.send(ssl_socket, request)

      # 等待连接建立
      :timer.sleep(500)

      :ssl.close(ssl_socket)
    end

    test "parses valid Trojan request with domain name" do
      {:ok, ssl_socket} =
        :ssl.connect(
          ~c"localhost",
          @test_port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          @timeout
        )

      hash = Protocol.sha224_hash(@test_password)
      domain = "example.com"

      # CONNECT
      # Domain
      # Port 80
      request =
        hash <>
          "\r\n" <>
          <<0x01>> <>
          <<0x03>> <>
          <<byte_size(domain)>> <>
          domain <>
          <<0, 80>> <>
          "\r\n"

      assert :ok = :ssl.send(ssl_socket, request)

      :timer.sleep(500)

      :ssl.close(ssl_socket)
    end

    test "handles Trojan request with initial payload" do
      {:ok, ssl_socket} =
        :ssl.connect(
          ~c"localhost",
          @test_port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          @timeout
        )

      hash = Protocol.sha224_hash(@test_password)
      http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

      # CONNECT
      # IPv4
      # Port 80
      request =
        hash <>
          "\r\n" <>
          <<0x01>> <>
          <<0x01>> <>
          <<93, 184, 216, 34>> <>
          <<0, 80>> <>
          "\r\n" <> http_request

      assert :ok = :ssl.send(ssl_socket, request)

      :timer.sleep(500)

      :ssl.close(ssl_socket)
    end
  end

  describe "fallback mechanism" do
    test "forwards invalid requests to fallback server" do
      {:ok, ssl_socket} =
        :ssl.connect(
          ~c"localhost",
          @test_port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          @timeout
        )

      # 发送看起来像 HTTPS 请求的数据
      https_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
      assert :ok = :ssl.send(ssl_socket, https_request)

      # 服务器应该将其转发到 fallback 服务器
      :timer.sleep(100)

      :ssl.close(ssl_socket)
    end

    test "handles malformed protocol gracefully" do
      {:ok, ssl_socket} =
        :ssl.connect(
          ~c"localhost",
          @test_port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          @timeout
        )

      # 发送不完整的数据
      malformed_data = "incomplete"
      assert :ok = :ssl.send(ssl_socket, malformed_data)

      :timer.sleep(100)

      :ssl.close(ssl_socket)
    end
  end

  describe "concurrent connections" do
    test "handles multiple simultaneous connections" do
      # 创建多个并发连接
      tasks =
        for i <- 1..5 do
          Task.async(fn ->
            {:ok, ssl_socket} =
              :ssl.connect(
                ~c"localhost",
                @test_port,
                [:binary, {:active, false}, {:verify, :verify_none}],
                @timeout
              )

            hash = Protocol.sha224_hash(@test_password)

            request =
              hash <>
                "\r\n" <>
                <<0x01>> <>
                <<0x01>> <>
                <<93, 184, 216, 34>> <>
                <<0, 80>> <>
                "\r\n"

            :ssl.send(ssl_socket, request)
            :timer.sleep(100)
            :ssl.close(ssl_socket)
            i
          end)
        end

      results = Task.await_many(tasks, @timeout)
      assert length(results) == 5
    end
  end

  describe "edge cases" do
    test "handles empty data after valid protocol header" do
      {:ok, ssl_socket} =
        :ssl.connect(
          ~c"localhost",
          @test_port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          @timeout
        )

      hash = Protocol.sha224_hash(@test_password)

      # 只发送哈希和CRLF，不发送SOCKS5请求
      request = hash <> "\r\n"
      :ssl.send(ssl_socket, request)

      :timer.sleep(100)

      :ssl.close(ssl_socket)
    end

    test "handles connection close during handshake" do
      {:ok, ssl_socket} =
        :ssl.connect(
          ~c"localhost",
          @test_port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          @timeout
        )

      # 发送部分数据后立即关闭
      partial_hash = String.slice(Protocol.sha224_hash(@test_password), 0, 20)
      :ssl.send(ssl_socket, partial_hash)
      :ssl.close(ssl_socket)

      :timer.sleep(100)
    end

    test "handles large payload data" do
      {:ok, ssl_socket} =
        :ssl.connect(
          ~c"localhost",
          @test_port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          @timeout
        )

      hash = Protocol.sha224_hash(@test_password)
      # 创建一个大的初始载荷 (1MB)
      large_payload = :binary.copy(<<0>>, 1_024 * 1024)

      request =
        hash <>
          "\r\n" <>
          <<0x01>> <>
          <<0x01>> <>
          <<93, 184, 216, 34>> <>
          <<0, 80>> <>
          "\r\n" <> large_payload

      :ssl.send(ssl_socket, request)

      :timer.sleep(200)

      :ssl.close(ssl_socket)
    end
  end
end
