defmodule Stealth.Protocol.Shadowsocks.WSHandlerTest do
  use ExUnit.Case
  alias Stealth.Protocol.Shadowsocks.{WSHandler, Cipher}

  describe "WebSocket handler initialization" do
    setup do
      {:ok, cipher} = Cipher.setup(:aes_256_gcm, "test-password")
      %{cipher: cipher}
    end

    test "initializes with cipher", %{cipher: cipher} do
      {:ok, state} = WSHandler.init(cipher: cipher)
      assert state.cipher == cipher
      assert state.state == :initial
      assert state.remote == nil
    end

    test "handles binary frame in initial state", %{cipher: cipher} do
      {:ok, state} = WSHandler.init(cipher: cipher)

      # This would fail without a proper handshake, but we're testing the structure
      result = WSHandler.handle_in({<<1, 2, 3>>, opcode: :binary}, state)

      # Should return error tuple or stop since the handshake data is invalid
      assert match?({:stop, :normal, _}, result)
    end

    test "ignores non-binary frames", %{cipher: cipher} do
      {:ok, state} = WSHandler.init(cipher: cipher)

      {:ok, new_state} = WSHandler.handle_in({~s({"test": "data"}), opcode: :text}, state)

      # Should ignore text frames
      assert new_state == state
    end
  end

  describe "WebSocket handler termination" do
    test "terminates cleanly" do
      {:ok, cipher} = Cipher.setup(:aes_256_gcm, "test-password")
      {:ok, state} = WSHandler.init(cipher: cipher)

      result = WSHandler.terminate(:normal, state)
      assert result == :ok
    end
  end
end
