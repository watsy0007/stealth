defmodule Stealth.Protocol.Trojan.ProtocolTest do
  use ExUnit.Case
  doctest Stealth.Protocol.Trojan.Protocol
  require Logger
  alias Stealth.Protocol.Trojan.Protocol

  test "protocol parsing" do
    password = "test_password_123"
    hash = Protocol.sha224_hash(password)

    Logger.info("Testing protocol parsing with password: #{password} and hash: #{hash}")

    assert byte_size(hash) == 56
  end
end
