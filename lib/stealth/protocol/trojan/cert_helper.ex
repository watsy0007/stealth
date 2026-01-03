defmodule Stealth.Protocol.Trojan.CertHelper do
  require Logger

  @cert_dir "priv/ssl"
  @key_file Path.join(@cert_dir, "server.key")
  @cert_file Path.join(@cert_dir, "server.crt")

  def setup_test_certificates do
    Logger.info("Setting up test SSL certificates...")

    File.mkdir_p!(@cert_dir)

    generate_basic_cert()

    verify_certificates()

    Logger.info("Test SSL certificates setup complete.")
    Logger.info("Key file: #{@key_file}")
    Logger.info("Certificate file: #{@cert_file}")

    {:ok, %{key_file: @key_file, cert_file: @cert_file}}
  end

  def generate_basic_cert do
    Logger.info("Generating basic SSL certificate...")

    # Ensure directory exists
    File.mkdir_p!(@cert_dir)

    # Remove old files if they exist (use File.rm not File.rm_rf for files)
    if File.exists?(@key_file), do: File.rm(@key_file)
    if File.exists?(@cert_file), do: File.rm(@cert_file)

    # Generate certificate
    case System.cmd(
           "openssl",
           [
             "req",
             "-x509",
             "-newkey",
             "rsa:2048",
             "-keyout",
             @key_file,
             "-out",
             @cert_file,
             "-days",
             "365",
             "-nodes",
             "-subj",
             "/CN=localhost"
           ], stderr_to_stdout: true) do
      {_out, 0} ->
        Logger.info("Basic SSL certificate generated successfully.")

      {error, code} ->
        Logger.error("Failed to generate basic SSL certificate: #{error} (exit code: #{code})")
        raise "Failed to generate basic SSL certificate"
    end
  end

  def verify_certificates do
    if File.exists?(@key_file) and File.exists?(@cert_file) do
      Logger.info("SSL key and certificate files exist.")
    else
      Logger.error("SSL key or certificate file is missing.")
      raise "SSL key or certificate file is missing"
    end

    case System.cmd("openssl", ["x509", "-in", @cert_file, "-text", "-noout"]) do
      {_out, 0} ->
        Logger.info("Certificate verification successful.")

      {error, code} ->
        Logger.error("Certificate verification failed: #{error} (exit code: #{code})")
        raise "Certificate verification failed"
    end
  end
end
