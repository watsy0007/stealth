defmodule Stealth.ConfigLoaderTest do
  use ExUnit.Case, async: false
  alias Stealth.ConfigLoader

  @test_config_dir Path.join([System.tmp_dir!(), "stealth_test_config"])
  @test_config_file Path.join(@test_config_dir, "test_config.yml")

  setup do
    # Create test config directory
    File.mkdir_p!(@test_config_dir)

    on_exit(fn ->
      # Cleanup test config directory
      File.rm_rf!(@test_config_dir)
    end)

    :ok
  end

  describe "load_config/1" do
    test "loads valid YAML configuration" do
      yaml_content = """
      shadowsocks:
        enabled: true
        port: 9088
        password: "test-password"
        method: "aes_128_gcm"
        websocket:
          enabled: false
          port: 9089

      trojan:
        enabled: true
        port: 8443
        password: "trojan-test"
        mask_host: "example.com"
        mask_port: 443
      """

      File.write!(@test_config_file, yaml_content)

      assert {:ok, config} = ConfigLoader.load_config(config_file: @test_config_file)
      assert is_map(config)
      assert config["shadowsocks"]["enabled"] == true
      assert config["shadowsocks"]["port"] == 9088
      assert config["shadowsocks"]["password"] == "test-password"
      assert config["trojan"]["enabled"] == true
      assert config["trojan"]["port"] == 8443
    end

    test "returns error for non-existent file" do
      non_existent_file = Path.join(@test_config_dir, "does_not_exist.yml")
      assert {:error, :file_not_found} = ConfigLoader.load_config(config_file: non_existent_file)
    end

    test "returns error for invalid YAML" do
      invalid_yaml = """
      this is not: [valid: yaml
      """

      File.write!(@test_config_file, invalid_yaml)

      assert {:error, _reason} = ConfigLoader.load_config(config_file: @test_config_file)
    end

    test "handles minimal configuration" do
      yaml_content = """
      shadowsocks:
        enabled: true
      """

      File.write!(@test_config_file, yaml_content)

      assert {:ok, config} = ConfigLoader.load_config(config_file: @test_config_file)
      assert config["shadowsocks"]["enabled"] == true
    end
  end

  describe "apply_yaml_config/0" do
    test "applies shadowsocks configuration correctly" do
      yaml_content = """
      shadowsocks:
        enabled: true
        port: 9088
        password: "test-ss-password"
        method: "aes_256_gcm"
        websocket:
          enabled: true
          port: 9089
      """

      File.write!(@test_config_file, yaml_content)

      # Set CONFIG_FILE env var to point to our test file
      System.put_env("CONFIG_FILE", @test_config_file)

      assert :ok = ConfigLoader.apply_yaml_config()

      # Verify application config was set correctly
      assert Application.get_env(:stealth, :enable_ss) == true
      ss_config = Application.get_env(:stealth, :ss)
      assert ss_config[:port] == 9088
      assert ss_config[:passwd] == "test-ss-password"
      assert ss_config[:method] == :aes_256_gcm
      assert ss_config[:ws_enabled] == true
      assert ss_config[:ws_port] == 9089

      # Cleanup
      System.delete_env("CONFIG_FILE")
    end

    test "applies trojan configuration correctly" do
      yaml_content = """
      trojan:
        enabled: true
        port: 8443
        password: "test-trojan-password"
        mask_host: "www.example.com"
        mask_port: 443
        certfile: "/path/to/cert.pem"
        keyfile: "/path/to/key.pem"
      """

      File.write!(@test_config_file, yaml_content)

      System.put_env("CONFIG_FILE", @test_config_file)

      assert :ok = ConfigLoader.apply_yaml_config()

      # Verify application config was set correctly
      assert Application.get_env(:stealth, :enable_trojan) == true
      trojan_config = Application.get_env(:stealth, :trojan)
      assert trojan_config[:port] == 8443
      assert trojan_config[:passwd] == "test-trojan-password"
      assert trojan_config[:mask_host] == "www.example.com"
      assert trojan_config[:mask_port] == 443
      assert trojan_config[:certfile] == "/path/to/cert.pem"
      assert trojan_config[:keyfile] == "/path/to/key.pem"

      # Cleanup
      System.delete_env("CONFIG_FILE")
    end

    test "uses default values when config values are missing" do
      yaml_content = """
      shadowsocks:
        enabled: true
        password: "minimal-config"
      """

      File.write!(@test_config_file, yaml_content)

      System.put_env("CONFIG_FILE", @test_config_file)

      assert :ok = ConfigLoader.apply_yaml_config()

      ss_config = Application.get_env(:stealth, :ss)
      # Should use defaults
      assert ss_config[:port] == 8088
      assert ss_config[:method] == :aes_256_gcm
      assert ss_config[:ws_port] == 8089

      # Cleanup
      System.delete_env("CONFIG_FILE")
    end

    test "returns :skip when no config file exists" do
      System.delete_env("CONFIG_FILE")
      non_existent = Path.join(@test_config_dir, "nonexistent.yml")
      System.put_env("CONFIG_FILE", non_existent)

      assert :skip = ConfigLoader.apply_yaml_config()

      System.delete_env("CONFIG_FILE")
    end
  end

  describe "configuration priority" do
    test "YAML config overrides environment variables" do
      # Set environment variables
      System.put_env("SS_PORT", "7777")
      System.put_env("SS_PASSWORD", "env-password")

      # Create YAML config with different values
      yaml_content = """
      shadowsocks:
        enabled: true
        port: 9999
        password: "yaml-password"
      """

      File.write!(@test_config_file, yaml_content)
      System.put_env("CONFIG_FILE", @test_config_file)

      assert :ok = ConfigLoader.apply_yaml_config()

      ss_config = Application.get_env(:stealth, :ss)
      # YAML values should take precedence
      assert ss_config[:port] == 9999
      assert ss_config[:passwd] == "yaml-password"

      # Cleanup
      System.delete_env("CONFIG_FILE")
      System.delete_env("SS_PORT")
      System.delete_env("SS_PASSWORD")
    end
  end
end
