defmodule Stealth.Protocol.Trojan.ProtocolTest do
  use ExUnit.Case, async: true
  doctest Stealth.Protocol.Trojan.Protocol
  require Logger
  alias Stealth.Protocol.Trojan.Protocol

  describe "sha224_hash/1" do
    test "generates correct hash length" do
      password = "test_password_123"
      hash = Protocol.sha224_hash(password)

      assert byte_size(hash) == 56
      assert is_binary(hash)
    end

    test "generates consistent hash for same password" do
      password = "my_secret_password"
      hash1 = Protocol.sha224_hash(password)
      hash2 = Protocol.sha224_hash(password)

      assert hash1 == hash2
    end

    test "generates different hashes for different passwords" do
      hash1 = Protocol.sha224_hash("password1")
      hash2 = Protocol.sha224_hash("password2")

      assert hash1 != hash2
    end

    test "generates lowercase hex string" do
      hash = Protocol.sha224_hash("test")

      # 验证是否为小写十六进制字符串
      assert Regex.match?(~r/^[a-f0-9]{56}$/, hash)
    end

    test "handles empty password" do
      hash = Protocol.sha224_hash("")

      assert byte_size(hash) == 56
    end

    test "handles unicode password" do
      hash = Protocol.sha224_hash("密码测试🔐")

      assert byte_size(hash) == 56
    end
  end

  describe "parse_request/2" do
    setup do
      # 创建一个模拟的 socket
      password = "test_password"
      hashed_password = Protocol.sha224_hash(password)

      # 构造有效的 Trojan 请求
      # 格式: hash + CRLF + CMD(0x01) + ATYP(0x01) + IPv4(4字节) + Port(2字节) + CRLF
      valid_request =
        hashed_password <>
          "\r\n" <>
          <<0x01>> <>
          # CONNECT
          <<0x01>> <>
          # IPv4
          <<93, 184, 216, 34>> <>
          # example.com IP
          <<0, 80>> <>
          # Port 80
          "\r\n"

      {:ok, password: password, hashed_password: hashed_password, valid_request: valid_request}
    end

    test "successfully parses valid IPv4 request", %{
      hashed_password: hashed_password,
      valid_request: valid_request
    } do
      # 创建一个模拟 socket
      {:ok, listen_socket} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(listen_socket)

      # 在后台接受连接
      task =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)
          wrapped_socket = %ThousandIsland.Socket{socket: socket}
          result = Protocol.parse_request(wrapped_socket, hashed_password)
          :gen_tcp.close(socket)
          result
        end)

      # 客户端连接并发送数据
      {:ok, client_socket} = :gen_tcp.connect(~c"localhost", port, [:binary, active: false])
      :gen_tcp.send(client_socket, valid_request)

      # 等待解析结果
      result = Task.await(task, 5000)

      assert {:ok, req} = result
      assert req.req_type == :ipv4
      assert req.ip == {93, 184, 216, 34}
      assert req.port == 80

      :gen_tcp.close(client_socket)
      :gen_tcp.close(listen_socket)
    end

    test "rejects request with invalid password", %{valid_request: valid_request} do
      wrong_password = Protocol.sha224_hash("wrong_password")

      {:ok, listen_socket} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(listen_socket)

      task =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)
          wrapped_socket = %ThousandIsland.Socket{socket: socket}
          result = Protocol.parse_request(wrapped_socket, wrong_password)
          :gen_tcp.close(socket)
          result
        end)

      {:ok, client_socket} = :gen_tcp.connect(~c"localhost", port, [:binary, active: false])
      :gen_tcp.send(client_socket, valid_request)

      result = Task.await(task, 5000)

      assert {:error, :invalid_protocol} = result

      :gen_tcp.close(client_socket)
      :gen_tcp.close(listen_socket)
    end

    test "parses request with domain name", %{hashed_password: hashed_password} do
      # 构造域名请求
      # 格式: hash + CRLF + CMD(0x01) + ATYP(0x03) + LEN(1字节) + domain + Port(2字节) + CRLF
      domain = "example.com"

      domain_request =
        hashed_password <>
          "\r\n" <>
          <<0x01>> <>
          # CONNECT
          <<0x03>> <>
          # Domain
          <<byte_size(domain)>> <>
          domain <>
          <<0, 80>> <>
          # Port 80
          "\r\n"

      {:ok, listen_socket} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(listen_socket)

      task =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)
          wrapped_socket = %ThousandIsland.Socket{socket: socket}
          result = Protocol.parse_request(wrapped_socket, hashed_password)
          :gen_tcp.close(socket)
          result
        end)

      {:ok, client_socket} = :gen_tcp.connect(~c"localhost", port, [:binary, active: false])
      :gen_tcp.send(client_socket, domain_request)

      result = Task.await(task, 5000)

      assert {:ok, req} = result
      assert req.req_type == :host
      assert req.addr == "example.com"
      assert req.port == 80

      :gen_tcp.close(client_socket)
      :gen_tcp.close(listen_socket)
    end

    test "handles request with initial payload", %{hashed_password: hashed_password} do
      # 构造带初始载荷的请求
      payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

      request_with_payload =
        hashed_password <>
          "\r\n" <>
          <<0x01>> <>
          # CONNECT
          <<0x01>> <>
          # IPv4
          <<93, 184, 216, 34>> <>
          <<0, 80>> <>
          # Port 80
          "\r\n" <> payload

      {:ok, listen_socket} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(listen_socket)

      task =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)
          wrapped_socket = %ThousandIsland.Socket{socket: socket}
          result = Protocol.parse_request(wrapped_socket, hashed_password)
          :gen_tcp.close(socket)
          result
        end)

      {:ok, client_socket} = :gen_tcp.connect(~c"localhost", port, [:binary, active: false])
      :gen_tcp.send(client_socket, request_with_payload)

      result = Task.await(task, 5000)

      assert {:ok, req} = result
      assert req.payload == payload
      assert byte_size(req.payload) > 0

      :gen_tcp.close(client_socket)
      :gen_tcp.close(listen_socket)
    end

    test "handles malformed request data" do
      hashed_password = Protocol.sha224_hash("test")
      invalid_data = "invalid data"

      {:ok, listen_socket} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(listen_socket)

      task =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)
          wrapped_socket = %ThousandIsland.Socket{socket: socket}
          result = Protocol.parse_request(wrapped_socket, hashed_password)
          :gen_tcp.close(socket)
          result
        end)

      {:ok, client_socket} = :gen_tcp.connect(~c"localhost", port, [:binary, active: false])
      :gen_tcp.send(client_socket, invalid_data)

      result = Task.await(task, 5000)

      assert {:error, _} = result

      :gen_tcp.close(client_socket)
      :gen_tcp.close(listen_socket)
    end
  end
end
