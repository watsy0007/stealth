defmodule Stealth.Protocol.Trojan.ProtocolTest do
  use ExUnit.Case, async: true
  doctest Stealth.Protocol.Trojan.Protocol
  require Logger
  alias Stealth.Protocol.Trojan.Protocol

  # Mock span for testing
  defmodule MockSpan do
    defstruct span_name: :test_span, span_metadata: %{}

    def span_metadata(%__MODULE__{}), do: %{}
  end

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

  describe "build_request/5" do
    test "builds valid IPv4 request" do
      {:ok, request} = Protocol.build_request("password", {192, 168, 1, 1}, 80)

      assert is_binary(request)
      # 验证包含密码哈希
      assert String.starts_with?(request, Protocol.sha224_hash("password"))
      # 验证包含 CRLF
      assert String.contains?(request, "\r\n")
    end

    test "builds valid domain request" do
      {:ok, request} = Protocol.build_request("password", "example.com", 443)

      assert is_binary(request)
      hash = Protocol.sha224_hash("password")
      assert String.starts_with?(request, hash)
    end

    test "builds request with payload" do
      payload = "GET / HTTP/1.1\r\n\r\n"
      {:ok, request} = Protocol.build_request("password", "example.com", 80, payload)

      assert String.ends_with?(request, payload)
    end

    test "builds request with UDP associate command" do
      {:ok, request} = Protocol.build_request("password", {8, 8, 8, 8}, 53, "", :udp_associate)

      assert is_binary(request)
      # 验证命令字节是 0x03
      hash = Protocol.sha224_hash("password")
      <<^hash::binary-size(56), "\r\n", 0x03, _rest::binary>> = request
    end
  end

  describe "build_socks5_address/3" do
    test "builds IPv4 address" do
      {:ok, addr} = Protocol.build_socks5_address({192, 168, 1, 1}, 80)

      assert addr == <<0x01, 0x01, 192, 168, 1, 1, 0, 80>>
    end

    test "builds IPv6 address" do
      {:ok, addr} = Protocol.build_socks5_address({0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1}, 443)

      assert <<0x01, 0x04, _rest::binary>> = addr
      assert byte_size(addr) == 20
    end

    test "builds domain address" do
      {:ok, addr} = Protocol.build_socks5_address("example.com", 443)

      assert <<0x01, 0x03, 11, "example.com", 1, 187>> = addr
    end

    test "rejects domain longer than 255 bytes" do
      long_domain = String.duplicate("a", 256)
      assert {:error, :domain_too_long} = Protocol.build_socks5_address(long_domain, 80)
    end

    test "builds address with UDP associate command" do
      {:ok, addr} = Protocol.build_socks5_address({8, 8, 8, 8}, 53, :udp_associate)

      assert <<0x03, 0x01, 8, 8, 8, 8, 0, 53>> = addr
    end

    test "builds address from parsed request map" do
      req = %{req_type: :ipv4, ip: {127, 0, 0, 1}, port: 8080}
      {:ok, addr} = Protocol.build_socks5_address(req, nil, :connect)

      assert <<0x01, 0x01, 127, 0, 0, 1, 31, 144>> = addr
    end

    test "handles invalid address" do
      assert {:error, :invalid_address} = Protocol.build_socks5_address(123, 80)
    end
  end

  describe "validate_password/2" do
    test "validates correct password" do
      hash = Protocol.sha224_hash("correct_password")
      assert Protocol.validate_password(hash, "correct_password")
    end

    test "rejects incorrect password" do
      hash = Protocol.sha224_hash("correct_password")
      refute Protocol.validate_password(hash, "wrong_password")
    end

    test "rejects malformed hash" do
      refute Protocol.validate_password("invalid_hash", "password")
    end
  end

  describe "extract_password_hash/1" do
    test "extracts valid password hash" do
      hash = Protocol.sha224_hash("password")
      data = hash <> "\r\n" <> "remaining data"

      assert {:ok, ^hash, "remaining data"} = Protocol.extract_password_hash(data)
    end

    test "handles insufficient data" do
      short_data = "too short"
      assert {:error, :insufficient_data} = Protocol.extract_password_hash(short_data)
    end

    test "handles invalid format" do
      # 56 字节但没有 CRLF
      invalid_data = String.duplicate("a", 56) <> "no crlf"
      assert {:error, :invalid_format} = Protocol.extract_password_hash(invalid_data)
    end
  end

  describe "command_name/1 and command_byte/1" do
    test "converts command byte to name" do
      assert Protocol.command_name(0x01) == :connect
      assert Protocol.command_name(0x03) == :udp_associate
      assert Protocol.command_name(0xFF) == :unknown
    end

    test "converts command name to byte" do
      assert Protocol.command_byte(:connect) == 0x01
      assert Protocol.command_byte(:udp_associate) == 0x03
      assert Protocol.command_byte(:unknown) == nil
    end
  end

  describe "parse_request/2" do
    setup do
      # 创建一个模拟的 socket
      password = "test_password"
      hashed_password = Protocol.sha224_hash(password)

      # 构造有效的 Trojan 请求
      # 格式: hash + CRLF + CMD(0x01) + ATYP(0x01) + IPv4(4字节) + Port(2字节) + CRLF
      # CONNECT
      # IPv4
      # example.com IP
      # Port 80
      valid_request =
        hashed_password <>
          "\r\n" <>
          <<0x01>> <>
          <<0x01>> <>
          <<93, 184, 216, 34>> <>
          <<0, 80>> <>
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
          wrapped_socket = %ThousandIsland.Socket{
            socket: socket,
            transport_module: ThousandIsland.Transports.TCP,
            read_timeout: 5000,
            silent_terminate_on_error: false,
            span: %MockSpan{}
          }
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
      assert req.addr == <<93, 184, 216, 34>>
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
          wrapped_socket = %ThousandIsland.Socket{
            socket: socket,
            transport_module: ThousandIsland.Transports.TCP,
            read_timeout: 5000,
            silent_terminate_on_error: false,
            span: %MockSpan{}
          }
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

      # CONNECT
      # Domain
      # Port 80
      domain_request =
        hashed_password <>
          "\r\n" <>
          <<0x01>> <>
          <<0x03>> <>
          <<byte_size(domain)>> <>
          domain <>
          <<0, 80>> <>
          "\r\n"

      {:ok, listen_socket} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(listen_socket)

      task =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)
          wrapped_socket = %ThousandIsland.Socket{
            socket: socket,
            transport_module: ThousandIsland.Transports.TCP,
            read_timeout: 5000,
            silent_terminate_on_error: false,
            span: %MockSpan{}
          }
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

      # CONNECT
      # IPv4
      # Port 80
      request_with_payload =
        hashed_password <>
          "\r\n" <>
          <<0x01>> <>
          <<0x01>> <>
          <<93, 184, 216, 34>> <>
          <<0, 80>> <>
          "\r\n" <> payload

      {:ok, listen_socket} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, port} = :inet.port(listen_socket)

      task =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)
          wrapped_socket = %ThousandIsland.Socket{
            socket: socket,
            transport_module: ThousandIsland.Transports.TCP,
            read_timeout: 5000,
            silent_terminate_on_error: false,
            span: %MockSpan{}
          }
          result = Protocol.parse_request(wrapped_socket, hashed_password)
          :gen_tcp.close(socket)
          result
        end)

      {:ok, client_socket} = :gen_tcp.connect(~c"localhost", port, [:binary, active: false])
      :gen_tcp.send(client_socket, request_with_payload)

      result = Task.await(task, 5000)

      assert {:ok, req} = result
      # Payload includes the trailing CRLF from the protocol
      assert req.payload == "\r\n" <> payload
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
          wrapped_socket = %ThousandIsland.Socket{
            socket: socket,
            transport_module: ThousandIsland.Transports.TCP,
            read_timeout: 5000,
            silent_terminate_on_error: false,
            span: %MockSpan{}
          }
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
