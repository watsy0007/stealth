defmodule Stealth.Protocol.Trojan.Crypto do
  @moduledoc """
  Cryptographic utilities for Trojan protocol.

  Provides SSL/TLS connection helpers and certificate validation.
  """

  require Logger

  @doc """
  Create SSL socket options for Trojan client connection.

  ## Parameters
    - host: Server hostname
    - opts: Additional SSL options (optional)

  ## Examples

      iex> Crypto.ssl_client_options("example.com")
      [
        server_name_indication: ~c"example.com",
        verify: :verify_peer,
        ...
      ]
  """
  def ssl_client_options(host, opts \\ []) do
    base_options = [
      active: false,
      packet: 0,
      nodelay: true,
      server_name_indication: String.to_charlist(host),
      verify: Keyword.get(opts, :verify, :verify_peer),
      cacerts: :public_key.cacerts_get(),
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ]
    ]

    [:binary | Keyword.merge(base_options, opts)]
  end

  @doc """
  Create SSL socket options for Trojan server.

  ## Parameters
    - cert_file: Path to certificate file
    - key_file: Path to private key file
    - opts: Additional SSL options (optional)

  ## Examples

      iex> Crypto.ssl_server_options("cert.pem", "key.pem")
      [
        certfile: ~c"cert.pem",
        keyfile: ~c"key.pem",
        ...
      ]
  """
  def ssl_server_options(cert_file, key_file, opts \\ []) do
    base_options = [
      certfile: String.to_charlist(cert_file),
      keyfile: String.to_charlist(key_file),
      verify: Keyword.get(opts, :verify, :verify_none),
      versions: [:"tlsv1.2", :"tlsv1.3"],
      ciphers: recommended_ciphers(),
      honor_cipher_order: true,
      secure_renegotiate: true
    ]

    Keyword.merge(base_options, opts)
  end

  @doc """
  Connect to Trojan server via SSL/TLS.

  ## Parameters
    - host: Server hostname or IP
    - port: Server port
    - opts: SSL options

  ## Examples

      iex> Crypto.ssl_connect("example.com", 443)
      {:ok, ssl_socket}
  """
  def ssl_connect(host, port, opts \\ []) when is_binary(host) and is_integer(port) do
    ssl_opts = ssl_client_options(host, opts)

    case :ssl.connect(String.to_charlist(host), port, ssl_opts, 10_000) do
      {:ok, socket} ->
        Logger.debug("SSL connection established to #{host}:#{port}")
        {:ok, socket}

      {:error, reason} = error ->
        Logger.error("Failed to establish SSL connection to #{host}:#{port}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Send data through SSL socket.

  ## Examples

      iex> Crypto.ssl_send(socket, "data")
      :ok
  """
  def ssl_send(socket, data) do
    :ssl.send(socket, data)
  end

  @doc """
  Receive data from SSL socket.

  ## Parameters
    - socket: SSL socket
    - length: Number of bytes to receive (0 for all available)
    - timeout: Timeout in milliseconds

  ## Examples

      iex> Crypto.ssl_recv(socket, 0, 5000)
      {:ok, data}
  """
  def ssl_recv(socket, length \\ 0, timeout \\ 5000) do
    :ssl.recv(socket, length, timeout)
  end

  @doc """
  Close SSL socket gracefully.

  ## Examples

      iex> Crypto.ssl_close(socket)
      :ok
  """
  def ssl_close(socket) do
    :ssl.close(socket)
  end

  @doc """
  Verify SSL certificate chain.

  ## Parameters
    - socket: SSL socket
    - expected_host: Expected hostname for verification

  ## Examples

      iex> Crypto.verify_certificate(socket, "example.com")
      {:ok, :valid}
  """
  def verify_certificate(socket, expected_host) do
    case :ssl.peercert(socket) do
      {:ok, cert_der} ->
        cert = :public_key.pkix_decode_cert(cert_der, :otp)

        case verify_hostname(cert, expected_host) do
          true ->
            Logger.debug("Certificate verification successful for #{expected_host}")
            {:ok, :valid}

          false ->
            Logger.warning("Certificate hostname mismatch for #{expected_host}")
            {:error, :hostname_mismatch}
        end

      {:error, reason} ->
        Logger.error("Failed to get peer certificate: #{inspect(reason)}")
        {:error, :no_certificate}
    end
  end

  @doc """
  Get SSL connection information.

  Returns cipher suite, protocol version, and other connection details.

  ## Examples

      iex> Crypto.connection_info(socket)
      {:ok, %{cipher: ..., version: ..., ...}}
  """
  def connection_info(socket) do
    case :ssl.connection_information(socket) do
      {:ok, info} ->
        {:ok,
         %{
           protocol: Keyword.get(info, :protocol),
           cipher_suite: Keyword.get(info, :cipher_suite),
           sni_hostname: Keyword.get(info, :sni_hostname)
         }}

      error ->
        error
    end
  end

  @doc """
  Perform SSL/TLS handshake.

  Useful for manual handshake control.

  ## Examples

      iex> Crypto.ssl_handshake(listen_socket, 5000)
      {:ok, ssl_socket}
  """
  def ssl_handshake(socket, timeout \\ 5000) do
    :ssl.handshake(socket, timeout)
  end

  # Private functions

  defp verify_hostname(cert, expected_host) do
    case :public_key.pkix_verify_hostname(
           cert,
           [{:dns_id, String.to_charlist(expected_host)}]
         ) do
      true -> true
      false -> false
    end
  end

  defp recommended_ciphers do
    # TLS 1.3 and 1.2 recommended cipher suites
    (:ssl.cipher_suites(:all, :"tlsv1.3") ++
       :ssl.cipher_suites(:all, :"tlsv1.2"))
    |> Enum.filter(&secure_cipher?/1)
  end

  defp secure_cipher?(cipher) do
    # Filter out weak ciphers
    cipher_name = :ssl.suite_to_str(cipher) |> to_string()

    not (String.contains?(cipher_name, "DES") or
           String.contains?(cipher_name, "RC4") or
           String.contains?(cipher_name, "MD5") or
           String.contains?(cipher_name, "NULL"))
  end
end
