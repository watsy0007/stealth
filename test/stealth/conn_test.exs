defmodule Stealth.ConnTest do
  use ExUnit.Case, async: true
  alias Stealth.Conn
  doctest Stealth.Conn

  describe "build_socks5_address/3" do
    test "builds IPv4 address" do
      {:ok, addr} = Conn.build_socks5_address({192, 168, 1, 1}, 80)

      assert addr == <<0x01, 0x01, 192, 168, 1, 1, 0, 80>>
    end

    test "builds IPv6 address" do
      {:ok, addr} = Conn.build_socks5_address({0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1}, 443)

      assert <<0x01, 0x04, _rest::binary>> = addr
      assert byte_size(addr) == 20
    end

    test "builds domain address" do
      {:ok, addr} = Conn.build_socks5_address("example.com", 443)

      assert <<0x01, 0x03, 11, "example.com", 1, 187>> = addr
    end

    test "rejects domain longer than 255 bytes" do
      long_domain = String.duplicate("a", 256)
      assert {:error, :domain_too_long} = Conn.build_socks5_address(long_domain, 80)
    end

    test "builds address with UDP associate command" do
      {:ok, addr} = Conn.build_socks5_address({8, 8, 8, 8}, 53, :udp_associate)

      assert <<0x03, 0x01, 8, 8, 8, 8, 0, 53>> = addr
    end

    test "builds address from parsed request map with IPv4" do
      req = %{req_type: :ipv4, ip: {127, 0, 0, 1}, port: 8080}
      {:ok, addr} = Conn.build_socks5_address(req, nil, :connect)

      assert <<0x01, 0x01, 127, 0, 0, 1, 31, 144>> = addr
    end

    test "builds address from parsed request map with domain" do
      req = %{req_type: :host, addr: "test.com", port: 443}
      {:ok, addr} = Conn.build_socks5_address(req, nil, :connect)

      assert <<0x01, 0x03, 8, "test.com", 1, 187>> = addr
    end

    test "handles invalid address" do
      assert {:error, :invalid_address} = Conn.build_socks5_address(123, 80)
    end
  end

  describe "parse_socks5_request/1" do
    test "parses IPv4 request with CMD byte" do
      data = <<0x01, 0x01, 127, 0, 0, 1, 0, 80, "payload">>
      {:ok, req} = Conn.parse_socks5_request(data)

      assert req.req_type == :ipv4
      assert req.addr == <<127, 0, 0, 1>>
      assert req.port == 80
      assert req.payload == "payload"
    end

    test "parses domain request with CMD byte" do
      data = <<0x01, 0x03, 11, "example.com", 0, 80, "data">>
      {:ok, req} = Conn.parse_socks5_request(data)

      assert req.req_type == :host
      assert req.addr == "example.com"
      assert req.port == 80
      assert req.payload == "data"
    end

    test "parses IPv6 request with CMD byte" do
      ipv6 = <<0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>
      data = <<0x01, 0x04>> <> ipv6 <> <<1, 187, "payload">>
      {:ok, req} = Conn.parse_socks5_request(data)

      assert req.req_type == :ipv6
      assert req.port == 443
    end

    test "parses legacy IPv4 request without CMD byte" do
      data = <<0x01, 192, 168, 1, 1, 0, 80, "payload">>
      {:ok, req} = Conn.parse_socks5_request(data)

      assert req.req_type == :ipv4
      assert req.addr == <<192, 168, 1, 1>>
      assert req.port == 80
    end

    test "parses legacy domain request without CMD byte" do
      data = <<0x03, 7, "test.io", 1, 187, "data">>
      {:ok, req} = Conn.parse_socks5_request(data)

      assert req.req_type == :host
      assert req.addr == "test.io"
      assert req.port == 443
    end

    test "handles invalid request" do
      assert {:error, :invalid_request} = Conn.parse_socks5_request(<<0xFF, 0xFF>>)
    end
  end

  describe "command_to_byte/1 and byte_to_command/1" do
    test "converts command name to byte" do
      assert Conn.command_to_byte(:connect) == 0x01
      assert Conn.command_to_byte(:bind) == 0x02
      assert Conn.command_to_byte(:udp_associate) == 0x03
      assert Conn.command_to_byte(:unknown) == nil
    end

    test "converts command byte to name" do
      assert Conn.byte_to_command(0x01) == :connect
      assert Conn.byte_to_command(0x02) == :bind
      assert Conn.byte_to_command(0x03) == :udp_associate
      assert Conn.byte_to_command(0xFF) == :unknown
    end
  end

  describe "roundtrip: build and parse" do
    test "IPv4 roundtrip" do
      {:ok, built} = Conn.build_socks5_address({192, 168, 1, 100}, 8080)
      {:ok, parsed} = Conn.parse_socks5_request(built <> "payload")

      assert parsed.req_type == :ipv4
      assert parsed.addr == <<192, 168, 1, 100>>
      assert parsed.port == 8080
      assert parsed.payload == "payload"
    end

    test "domain roundtrip" do
      {:ok, built} = Conn.build_socks5_address("example.org", 443)
      {:ok, parsed} = Conn.parse_socks5_request(built <> "data")

      assert parsed.req_type == :host
      assert parsed.addr == "example.org"
      assert parsed.port == 443
      assert parsed.payload == "data"
    end

    test "IPv6 roundtrip" do
      ipv6 = {0x2001, 0x0DB8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}
      {:ok, built} = Conn.build_socks5_address(ipv6, 80)
      {:ok, parsed} = Conn.parse_socks5_request(built <> "test")

      assert parsed.req_type == :ipv6
      assert parsed.port == 80
      assert parsed.payload == "test"
    end
  end
end
