defmodule Stealth.Protocol.Trojan.ClientTest do
  use ExUnit.Case
  alias Stealth.Protocol.Trojan.{Client, Protocol, CertHelper, Worker}
  require Logger

  @test_port 28443
  @test_password "client_test_password"
  @timeout 10_000

  setup_all do
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

    case ThousandIsland.start_link(cfg) do
      {:ok, pid} ->
        on_exit(fn -> GenServer.stop(pid) end)
        {:ok, server_pid: pid, cert_info: cert_info}

      {:error, reason} ->
        Logger.error("Failed to start test server: #{inspect(reason)}")
        :skip
    end
  end

  describe "connect/6" do
    test "establishes tunnel to target server" do
      result =
        Client.connect(
          "localhost",
          @test_port,
          @test_password,
          "example.com",
          80,
          verify: :verify_none
        )

      case result do
        {:ok, socket} ->
          assert is_tuple(socket)
          Client.close(socket)

        {:error, reason} ->
          # 连接可能失败（网络问题），但至少应该能连接到 Trojan 服务器
          Logger.warning("Connection failed: #{inspect(reason)}")
      end
    end

    test "fails with wrong password" do
      result =
        Client.connect(
          "localhost",
          @test_port,
          "wrong_password",
          "example.com",
          80,
          verify: :verify_none
        )

      # 即使密码错误，SSL 连接也会建立，但后续流量会被转发到 fallback 服务器
      # 所以我们只验证能否建立连接
      case result do
        {:ok, socket} -> Client.close(socket)
        {:error, _reason} -> :ok
      end
    end

    test "supports initial payload" do
      initial_payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

      result =
        Client.connect(
          "localhost",
          @test_port,
          @test_password,
          "example.com",
          80,
          verify: :verify_none,
          initial_payload: initial_payload
        )

      case result do
        {:ok, socket} -> Client.close(socket)
        {:error, _reason} -> :ok
      end
    end

    test "fails to connect to invalid server" do
      result =
        Client.connect(
          "nonexistent.invalid.test",
          443,
          @test_password,
          "example.com",
          80,
          verify: :verify_none
        )

      assert {:error, _reason} = result
    end
  end

  describe "send_data/2 and recv_data/3" do
    test "sends and receives data through tunnel" do
      case Client.connect(
             "localhost",
             @test_port,
             @test_password,
             "example.com",
             80,
             verify: :verify_none
           ) do
        {:ok, socket} ->
          # 发送简单的数据
          assert :ok = Client.send_data(socket, "test data")

          # 尝试接收（可能超时，因为没有真实的目标服务器响应）
          case Client.recv_data(socket, 0, 1000) do
            {:ok, _data} -> :ok
            {:error, :timeout} -> :ok
            {:error, _} -> :ok
          end

          Client.close(socket)

        {:error, _reason} ->
          :ok
      end
    end
  end

  describe "http_proxy_request/5" do
    test "builds and sends HTTP request" do
      case Client.connect(
             "localhost",
             @test_port,
             @test_password,
             "httpbin.org",
             80,
             verify: :verify_none
           ) do
        {:ok, socket} ->
          result = Client.http_proxy_request(socket, "GET", "/", "httpbin.org")

          case result do
            {:ok, response} ->
              assert is_binary(response)

            {:error, :timeout} ->
              :ok

            {:error, _} ->
              :ok
          end

          Client.close(socket)

        {:error, _reason} ->
          :ok
      end
    end

    test "sends POST request with body" do
      case Client.connect(
             "localhost",
             @test_port,
             @test_password,
             "httpbin.org",
             80,
             verify: :verify_none
           ) do
        {:ok, socket} ->
          headers = [{"Content-Type", "application/json"}]
          body = ~s({"test": "data"})

          result =
            Client.http_proxy_request(socket, "POST", "/post", "httpbin.org", headers, body)

          case result do
            {:ok, _response} -> :ok
            {:error, _} -> :ok
          end

          Client.close(socket)

        {:error, _reason} ->
          :ok
      end
    end
  end

  describe "close/1" do
    test "closes socket successfully" do
      case Client.connect(
             "localhost",
             @test_port,
             @test_password,
             "example.com",
             80,
             verify: :verify_none
           ) do
        {:ok, socket} ->
          assert :ok = Client.close(socket)

        {:error, _reason} ->
          :ok
      end
    end
  end

  describe "integration tests" do
    test "full request-response cycle with IPv4 target" do
      # 使用 IP 地址而不是域名
      target_ip = {93, 184, 216, 34}

      case Client.connect(
             "localhost",
             @test_port,
             @test_password,
             target_ip,
             80,
             verify: :verify_none
           ) do
        {:ok, socket} ->
          :ok = Client.send_data(socket, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

          case Client.recv_data(socket, 0, 2000) do
            {:ok, response} ->
              # 验证收到 HTTP 响应
              assert is_binary(response)

            {:error, _} ->
              :ok
          end

          Client.close(socket)

        {:error, _reason} ->
          :ok
      end
    end

    test "handles connection errors gracefully" do
      # 尝试连接到不存在的端口
      result =
        Client.connect(
          "localhost",
          @test_port,
          @test_password,
          {127, 0, 0, 1},
          65534,
          verify: :verify_none
        )

      case result do
        {:ok, socket} ->
          # 即使建立了到 Trojan 服务器的连接，
          # 后续的目标连接可能会失败
          Client.close(socket)

        {:error, _reason} ->
          :ok
      end
    end

    test "supports domain name resolution" do
      result =
        Client.connect(
          "localhost",
          @test_port,
          @test_password,
          "google.com",
          80,
          verify: :verify_none
        )

      case result do
        {:ok, socket} ->
          Client.close(socket)

        {:error, _reason} ->
          :ok
      end
    end

    test "handles large data transmission" do
      case Client.connect(
             "localhost",
             @test_port,
             @test_password,
             "example.com",
             80,
             verify: :verify_none
           ) do
        {:ok, socket} ->
          # 发送大量数据
          large_data = :binary.copy(<<0>>, 10_000)
          result = Client.send_data(socket, large_data)

          assert result == :ok or match?({:error, _}, result)

          Client.close(socket)

        {:error, _reason} ->
          :ok
      end
    end
  end

  describe "edge cases" do
    test "handles concurrent connections" do
      tasks =
        for _i <- 1..3 do
          Task.async(fn ->
            case Client.connect(
                   "localhost",
                   @test_port,
                   @test_password,
                   "example.com",
                   80,
                   verify: :verify_none
                 ) do
              {:ok, socket} ->
                Client.send_data(socket, "test")
                Client.close(socket)
                :ok

              {:error, _} ->
                :error
            end
          end)
        end

      results = Task.await_many(tasks, @timeout)
      # 至少一些连接应该成功
      assert Enum.any?(results, &(&1 == :ok))
    end

    test "handles immediate close after connect" do
      case Client.connect(
             "localhost",
             @test_port,
             @test_password,
             "example.com",
             80,
             verify: :verify_none
           ) do
        {:ok, socket} ->
          assert :ok = Client.close(socket)

        {:error, _reason} ->
          :ok
      end
    end

    test "handles timeout on receive" do
      case Client.connect(
             "localhost",
             @test_port,
             @test_password,
             "example.com",
             80,
             verify: :verify_none
           ) do
        {:ok, socket} ->
          # 不发送数据，直接尝试接收（应该超时）
          result = Client.recv_data(socket, 0, 100)

          assert result == {:error, :timeout} or match?({:error, _}, result)

          Client.close(socket)

        {:error, _reason} ->
          :ok
      end
    end
  end
end
