defmodule Stealth.Protocol.Trojan.CertHelperTest do
  use ExUnit.Case
  alias Stealth.Protocol.Trojan.CertHelper
  require Logger

  @test_cert_dir "priv/ssl_test"
  @test_key_file Path.join(@test_cert_dir, "test_server.key")
  @test_cert_file Path.join(@test_cert_dir, "test_server.crt")

  setup do
    # 清理测试目录
    on_exit(fn ->
      File.rm_rf(@test_cert_dir)
    end)

    :ok
  end

  describe "setup_test_certificates/0" do
    test "creates SSL directory and certificate files" do
      {:ok, cert_info} = CertHelper.setup_test_certificates()

      assert File.exists?(cert_info.cert_file)
      assert File.exists?(cert_info.key_file)
      assert cert_info.cert_file =~ ~r/server\.crt$/
      assert cert_info.key_file =~ ~r/server\.key$/
    end

    test "generates valid certificate files" do
      {:ok, cert_info} = CertHelper.setup_test_certificates()

      # 验证证书文件不为空
      cert_content = File.read!(cert_info.cert_file)
      key_content = File.read!(cert_info.key_file)

      assert byte_size(cert_content) > 0
      assert byte_size(key_content) > 0

      # 验证证书格式
      assert cert_content =~ "-----BEGIN CERTIFICATE-----"
      assert cert_content =~ "-----END CERTIFICATE-----"

      # 验证私钥格式
      assert key_content =~ "-----BEGIN"
      assert key_content =~ "-----END"
    end

    test "can be called multiple times" do
      # 第一次调用
      {:ok, cert_info1} = CertHelper.setup_test_certificates()
      assert File.exists?(cert_info1.cert_file)

      # 第二次调用应该覆盖现有文件
      {:ok, cert_info2} = CertHelper.setup_test_certificates()
      assert File.exists?(cert_info2.cert_file)
      assert cert_info1.cert_file == cert_info2.cert_file
    end
  end

  describe "generate_basic_cert/0" do
    test "generates RSA certificate and key" do
      CertHelper.generate_basic_cert()

      cert_dir = "priv/ssl"
      key_file = Path.join(cert_dir, "server.key")
      cert_file = Path.join(cert_dir, "server.crt")

      assert File.exists?(key_file)
      assert File.exists?(cert_file)

      # 清理
      File.rm_rf(cert_dir)
    end

    test "overwrites existing certificates" do
      CertHelper.generate_basic_cert()

      cert_dir = "priv/ssl"
      cert_file = Path.join(cert_dir, "server.crt")

      # 获取第一次生成的修改时间
      %{mtime: mtime1} = File.stat!(cert_file)

      # 等待一小段时间确保时间戳不同
      :timer.sleep(1000)

      # 再次生成
      CertHelper.generate_basic_cert()

      # 验证文件已被覆盖
      %{mtime: mtime2} = File.stat!(cert_file)
      assert mtime2 > mtime1

      # 清理
      File.rm_rf(cert_dir)
    end
  end

  describe "verify_certificates/0" do
    test "verifies valid certificates" do
      CertHelper.setup_test_certificates()

      # 验证应该成功
      assert :ok == CertHelper.verify_certificates()

      # 清理
      File.rm_rf("priv/ssl")
    end

    test "raises when certificate file is missing" do
      cert_dir = "priv/ssl"
      # 清理并创建新目录
      File.rm_rf(cert_dir)
      File.mkdir_p!(cert_dir)

      # 只创建 key 文件，不创建 cert 文件
      key_file = Path.join(cert_dir, "server.key")
      File.write!(key_file, "fake key content")

      assert_raise RuntimeError, ~r/SSL key or certificate file is missing/, fn ->
        CertHelper.verify_certificates()
      end

      # 清理
      File.rm_rf(cert_dir)
    end

    test "raises when key file is missing" do
      cert_dir = "priv/ssl"
      # 清理并创建新目录
      File.rm_rf(cert_dir)
      File.mkdir_p!(cert_dir)

      # 只创建 cert 文件，不创建 key 文件
      cert_file = Path.join(cert_dir, "server.crt")
      File.write!(cert_file, "fake cert content")

      assert_raise RuntimeError, ~r/SSL key or certificate file is missing/, fn ->
        CertHelper.verify_certificates()
      end

      # 清理
      File.rm_rf(cert_dir)
    end
  end

  describe "integration test" do
    test "generated certificates can be loaded by SSL library" do
      {:ok, cert_info} = CertHelper.setup_test_certificates()

      # 尝试使用 SSL 库加载证书
      cert_content = File.read!(cert_info.cert_file)
      [cert_pem_entry | _] = :public_key.pem_decode(cert_content)

      # Extract DER binary from PEM entry
      cert_der_binary = elem(cert_pem_entry, 1)

      # Decode the DER binary to OTP certificate format
      otp_cert = :public_key.pkix_decode_cert(cert_der_binary, :otp)

      # 验证证书结构
      assert elem(otp_cert, 0) == :OTPCertificate
      assert otp_cert != nil

      # 清理
      File.rm_rf("priv/ssl")
    end

    test "generated key and certificate can start SSL server" do
      {:ok, cert_info} = CertHelper.setup_test_certificates()

      # 尝试启动一个 SSL 服务器
      ssl_options = [
        certfile: String.to_charlist(cert_info.cert_file),
        keyfile: String.to_charlist(cert_info.key_file),
        verify: :verify_none
      ]

      {:ok, listen_socket} =
        :ssl.listen(0, [:binary, {:active, false}, {:reuseaddr, true} | ssl_options])

      {:ok, {_addr, port}} = :ssl.sockname(listen_socket)
      assert port > 0

      :ssl.close(listen_socket)

      # 清理
      File.rm_rf("priv/ssl")
    end
  end
end
