defmodule Stealth.CiperStreamTest do
  use ExUnit.Case, async: true
  require Logger
  alias Stealth.Cipher

  @passwd "foQuC36lejke0X0FkHBbVAJAWiZlGtFO5vKhiduv+is="
  @data "Something needs to be encrypted"
  @more_data "One thing I've learned in the woods is that there is no such thing as random. Everything is steeped in meaning, colored by relationships, one thing with another."
  @methods ~w(
    aes_128_gcm
    aes_256_gcm
  )a

  for method <- @methods do
    test "#{method} encode/decode" do
      {:ok, c} = Cipher.setup(unquote(method), @passwd)
      {:ok, c, salt} = Cipher.init_encoder(c)
      {:ok, c} = Cipher.init_decoder(c, salt)
      {:ok, _, res} = Cipher.encode(c, @data)
      {:ok, _, data} = Cipher.decode(c, res)
      assert data == @data
    end

    test "#{method} stream_encode/stream_decode" do
      {:ok, c} = Cipher.setup(unquote(method), @passwd)
      {:ok, c, salt} = Cipher.init_encoder(c)
      {:ok, c} = Cipher.init_decoder(c, salt)

      {:ok, c, res} = Cipher.stream_encode(c, @data)
      {:ok, c, more} = Cipher.stream_encode(c, @more_data)
      {:ok, c, data} = Cipher.stream_decode(c, res)
      {:ok, _, more_data} = Cipher.stream_decode(c, more)

      assert data == @data
      assert more_data == @more_data
    end

    test "#{method} stream_encode/stream_decode with different decode chunk size" do
      {:ok, c} = Cipher.setup(unquote(method), @passwd)
      {:ok, c, salt} = Cipher.init_encoder(c)
      {:ok, c} = Cipher.init_decoder(c, salt)

      {:ok, c, res} = Cipher.stream_encode(c, @data)
      {:ok, c, more} = Cipher.stream_encode(c, @more_data)
      {:ok, _, all} = Cipher.stream_decode(c, res <> more)

      assert all == @data <> @more_data
    end

    test "#{method} stream_encode/stream_decode with large size" do
      {:ok, c} = Cipher.setup(unquote(method), @passwd)
      {:ok, c, salt} = Cipher.init_encoder(c)
      {:ok, c} = Cipher.init_decoder(c, salt)

      pre_encode = :binary.copy(@more_data, 10000)
      {:ok, c, res} = Cipher.stream_encode(c, pre_encode)
      {:ok, _, all} = Cipher.stream_decode(c, res)

      assert all == pre_encode
    end
  end
end
