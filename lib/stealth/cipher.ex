defmodule Stealth.Cipher do
  @type method :: atom()
  @type ctx :: tuple()
  @type t :: %__MODULE__{}

  require Logger
  alias Stealth.Cipher
  alias Stealth.HKDF

  defstruct method: nil, key: nil, encoder: nil, decoder: nil, key_len: 0, iv_len: 0

  @methods %{
    # { key_len, iv_len | salt_len }
    aes_128_gcm: {16, 16},
    aes_256_gcm: {32, 32}
  }

  @spec setup(atom(), String.t()) :: {:ok, t} | {:error, :invalid_method}
  def setup(method, _) when not is_map_key(@methods, method), do: {:error, :invalid_method}

  def setup(method, passwd) do
    {key_len, iv_len} = @methods[method]

    res = %__MODULE__{
      method: method,
      key_len: key_len,
      iv_len: iv_len,
      key: evp_bytes_to_key(passwd, key_len, iv_len)
    }

    {:ok, res}
  end

  @spec init_encoder(t()) :: {:ok, t(), binary()}
  def init_encoder(%Cipher{key: key, iv_len: iv_len} = c) do
    salt = :crypto.strong_rand_bytes(iv_len)
    sub_key = compute_sub_key(key, salt)
    {:ok, %{c | encoder: {sub_key, 0}}, salt}
  end

  @spec init_decoder(t(), binary()) :: {:ok, t()}
  def init_decoder(%Cipher{key: key} = c, salt) do
    sub_key = compute_sub_key(key, salt)
    {:ok, %{c | decoder: {sub_key, 0}}}
  end

  def stream_encode(c, data) when byte_size(data) > 0x3FFF do
    {first, rest} = :erlang.split_binary(data, 0x3FFF)
    {:ok, c, res} = stream_encode(c, first)
    {:ok, c, more} = stream_encode(c, rest)
    {:ok, c, res <> more}
  end

  def stream_encode(c, data) do
    l = byte_size(data)
    {:ok, c, len} = encode(c, <<l::16>>)
    {:ok, c, res} = encode(c, data)
    {:ok, c, len <> res}
  end

  def stream_decode(c, ""), do: {:ok, c, ""}

  def stream_decode(%Cipher{decoder: {key, nonce, buf}} = c, data) do
    stream_decode(%{c | decoder: {key, nonce}}, buf <> data)
  end

  def stream_decode(c, <<len::bytes-18, rest::bytes>> = data) do
    case decode(c, len) do
      # not enough data for a full package decode, leave it for next time
      {:ok, _, <<len::16>>} when len + 16 > byte_size(rest) ->
        {key, nonce} = c.decoder
        {:ok, %{c | decoder: {key, nonce, data}}, ""}

      {:ok, c, <<len::16>>} ->
        data_len = len + 16

        case rest do
          <<payload::bytes-size(data_len)>> ->
            with {:ok, c, res} <- decode(c, payload), do: {:ok, c, res}

          <<payload::bytes-size(data_len), next::bytes>> ->
            with {:ok, c, res} <- decode(c, payload),
                 {:ok, c, more} <- stream_decode(c, next),
                 do: {:ok, c, res <> more}
        end

      # error decoding length
      {:error, reason} ->
        {:error, reason}
    end
  end

  def stream_decode(%Cipher{decoder: {key, nonce}} = c, data) do
    {:ok, %{c | decoder: {key, nonce, data}}, ""}
  end

  @spec encode(t(), String.t()) :: {:ok, t(), binary()}
  def encode(%Cipher{encoder: {key, nonce}, method: method} = c, data) do
    {res, tag} = :crypto.crypto_one_time_aead(method, key, <<nonce::little-96>>, data, <<>>, true)
    {:ok, %{c | encoder: {key, nonce + 1}}, res <> tag}
  end

  @spec decode(t(), binary()) :: {:ok, t(), binary()} | {:error, :forged}
  def decode(%Cipher{decoder: {key, nonce}, method: method} = c, data) do
    payload_len = byte_size(data) - 16
    {payload, tag} = :erlang.split_binary(data, payload_len)

    res =
      :crypto.crypto_one_time_aead(method, key, <<nonce::little-96>>, payload, <<>>, tag, false)

    case res do
      r when is_binary(r) -> {:ok, %{c | decoder: {key, nonce + 1}}, r}
      :error -> {:error, :forged}
    end
  end

  defp evp_bytes_to_key(passwd, key_len, iv_ken) do
    evp_bytes_to_key(passwd, key_len, iv_ken, "")
  end

  defp evp_bytes_to_key(_, key_len, iv_ken, bytes)
       when byte_size(bytes) > key_len + iv_ken do
    <<key::bytes-size(key_len), _::bytes>> = bytes
    key
  end

  defp evp_bytes_to_key(passwd, key_len, iv_ken, bytes) do
    evp_bytes_to_key(passwd, key_len, iv_ken, bytes <> :crypto.hash(:md5, bytes <> passwd))
  end

  defp compute_sub_key(key, salt) do
    HKDF.derive(:sha, key, byte_size(salt), salt, "ss-subkey")
  end
end
