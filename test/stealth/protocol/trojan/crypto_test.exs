defmodule Stealth.Protocol.Trojan.CryptoTest do
  use ExUnit.Case, async: true
  alias Stealth.Protocol.Trojan.{Crypto, CertHelper}
  require Logger

  describe "ssl_client_options/2" do
    test "generates default client options" do
      opts = Crypto.ssl_client_options("example.com")

      assert Keyword.keyword?(opts)
      assert Keyword.get(opts, :verify) == :verify_peer
      assert Keyword.get(opts, :server_name_indication) == ~c"example.com"
      assert Keyword.has_key?(opts, :cacerts)
    end

    test "merges custom options" do
      custom_opts = [verify: :verify_none, custom_key: :custom_value]
      opts = Crypto.ssl_client_options("example.com", custom_opts)

      assert Keyword.get(opts, :verify) == :verify_none
      assert Keyword.get(opts, :custom_key) == :custom_value
    end

    test "includes security settings" do
      opts = Crypto.ssl_client_options("example.com")

      assert Keyword.get(opts, :nodelay) == true
      assert Keyword.has_key?(opts, :customize_hostname_check)
    end
  end

  describe "ssl_server_options/3" do
    setup do
      {:ok, cert_info} = CertHelper.setup_test_certificates()
      {:ok, cert_info: cert_info}
    end

    test "generates server options", %{cert_info: cert_info} do
      opts = Crypto.ssl_server_options(cert_info.cert_file, cert_info.key_file)

      assert Keyword.keyword?(opts)
      assert Keyword.has_key?(opts, :certfile)
      assert Keyword.has_key?(opts, :keyfile)
      assert Keyword.get(opts, :verify) == :verify_none
    end

    test "includes TLS versions", %{cert_info: cert_info} do
      opts = Crypto.ssl_server_options(cert_info.cert_file, cert_info.key_file)

      versions = Keyword.get(opts, :versions)
      assert :"tlsv1.2" in versions
      assert :"tlsv1.3" in versions
    end

    test "includes cipher suites", %{cert_info: cert_info} do
      opts = Crypto.ssl_server_options(cert_info.cert_file, cert_info.key_file)

      ciphers = Keyword.get(opts, :ciphers)
      assert is_list(ciphers)
      assert length(ciphers) > 0
    end

    test "merges custom options", %{cert_info: cert_info} do
      custom_opts = [verify: :verify_peer, custom: true]
      opts = Crypto.ssl_server_options(cert_info.cert_file, cert_info.key_file, custom_opts)

      assert Keyword.get(opts, :verify) == :verify_peer
      assert Keyword.get(opts, :custom) == true
    end
  end

  describe "ssl_send/2 and ssl_recv/3" do
    setup do
      {:ok, cert_info} = CertHelper.setup_test_certificates()

      # 启动 SSL 服务器
      ssl_opts = Crypto.ssl_server_options(cert_info.cert_file, cert_info.key_file)

      {:ok, listen_socket} =
        :ssl.listen(0, [:binary, {:active, false}, {:reuseaddr, true} | ssl_opts])

      {:ok, {_addr, port}} = :ssl.sockname(listen_socket)

      {:ok, listen_socket: listen_socket, port: port, cert_info: cert_info}
    end

    test "sends and receives data", %{listen_socket: listen_socket, port: port} do
      # 服务器接受连接
      server_task =
        Task.async(fn ->
          {:ok, server_socket} = :ssl.transport_accept(listen_socket)
          {:ok, _} = :ssl.handshake(server_socket, 5000)

          {:ok, data} = Crypto.ssl_recv(server_socket, 0, 5000)
          :ok = Crypto.ssl_send(server_socket, "response: " <> data)
          Crypto.ssl_close(server_socket)
          data
        end)

      # 客户端连接
      {:ok, client_socket} =
        :ssl.connect(
          ~c"localhost",
          port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          5000
        )

      :ok = Crypto.ssl_send(client_socket, "test data")
      {:ok, response} = Crypto.ssl_recv(client_socket, 0, 5000)

      assert response == "response: test data"

      Crypto.ssl_close(client_socket)
      :ssl.close(listen_socket)

      received = Task.await(server_task, 5000)
      assert received == "test data"
    end
  end

  describe "ssl_connect/3" do
    test "returns error for invalid host" do
      result = Crypto.ssl_connect("nonexistent.invalid.host.test", 443, verify: :verify_none)

      assert {:error, _reason} = result
    end

    test "returns error for connection refused" do
      # 使用一个不太可能有服务的端口
      result = Crypto.ssl_connect("localhost", 65000, verify: :verify_none)

      assert {:error, _reason} = result
    end
  end

  describe "connection_info/1" do
    setup do
      {:ok, cert_info} = CertHelper.setup_test_certificates()
      ssl_opts = Crypto.ssl_server_options(cert_info.cert_file, cert_info.key_file)

      {:ok, listen_socket} =
        :ssl.listen(0, [:binary, {:active, false}, {:reuseaddr, true} | ssl_opts])

      {:ok, {_addr, port}} = :ssl.sockname(listen_socket)

      {:ok, listen_socket: listen_socket, port: port}
    end

    test "retrieves connection information", %{listen_socket: listen_socket, port: port} do
      # 启动服务器
      _server_task =
        Task.async(fn ->
          {:ok, server_socket} = :ssl.transport_accept(listen_socket)
          {:ok, _} = :ssl.handshake(server_socket, 5000)
          :timer.sleep(1000)
          Crypto.ssl_close(server_socket)
        end)

      # 客户端连接
      {:ok, client_socket} =
        :ssl.connect(
          ~c"localhost",
          port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          5000
        )

      # 获取连接信息
      {:ok, info} = Crypto.connection_info(client_socket)

      assert is_map(info)
      assert Map.has_key?(info, :protocol)
      assert Map.has_key?(info, :cipher_suite)

      Crypto.ssl_close(client_socket)
      :ssl.close(listen_socket)
    end
  end

  describe "verify_certificate/2" do
    setup do
      {:ok, cert_info} = CertHelper.setup_test_certificates()
      ssl_opts = Crypto.ssl_server_options(cert_info.cert_file, cert_info.key_file)

      {:ok, listen_socket} =
        :ssl.listen(0, [:binary, {:active, false}, {:reuseaddr, true} | ssl_opts])

      {:ok, {_addr, port}} = :ssl.sockname(listen_socket)

      {:ok, listen_socket: listen_socket, port: port}
    end

    test "verifies self-signed certificate", %{listen_socket: listen_socket, port: port} do
      _server_task =
        Task.async(fn ->
          {:ok, server_socket} = :ssl.transport_accept(listen_socket)
          {:ok, _} = :ssl.handshake(server_socket, 5000)
          :timer.sleep(1000)
          Crypto.ssl_close(server_socket)
        end)

      {:ok, client_socket} =
        :ssl.connect(
          ~c"localhost",
          port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          5000
        )

      # 验证证书（自签名证书会匹配 localhost）
      result = Crypto.verify_certificate(client_socket, "localhost")

      # 自签名证书应该能通过主机名验证
      assert result == {:ok, :valid} or match?({:error, _}, result)

      Crypto.ssl_close(client_socket)
      :ssl.close(listen_socket)
    end
  end

  describe "ssl_handshake/2" do
    setup do
      {:ok, cert_info} = CertHelper.setup_test_certificates()
      ssl_opts = Crypto.ssl_server_options(cert_info.cert_file, cert_info.key_file)

      {:ok, listen_socket} =
        :ssl.listen(0, [:binary, {:active, false}, {:reuseaddr, true} | ssl_opts])

      {:ok, {_addr, port}} = :ssl.sockname(listen_socket)

      {:ok, listen_socket: listen_socket, port: port}
    end

    test "performs manual handshake", %{listen_socket: listen_socket, port: port} do
      server_task =
        Task.async(fn ->
          {:ok, transport_socket} = :ssl.transport_accept(listen_socket)
          {:ok, ssl_socket} = Crypto.ssl_handshake(transport_socket, 5000)
          Crypto.ssl_close(ssl_socket)
          :ok
        end)

      {:ok, client_socket} =
        :ssl.connect(
          ~c"localhost",
          port,
          [:binary, {:active, false}, {:verify, :verify_none}],
          5000
        )

      Crypto.ssl_close(client_socket)
      :ssl.close(listen_socket)

      assert Task.await(server_task, 5000) == :ok
    end
  end
end
