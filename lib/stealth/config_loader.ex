defmodule Stealth.ConfigLoader do
  @moduledoc """
  Loads configuration from YAML files and converts to application config format.

  Supports loading configuration from a YAML file specified by the `CONFIG_FILE`
  environment variable, or falls back to default `config/stealth.yml` if present.

  ## YAML Configuration Format

  ```yaml
  shadowsocks:
    enabled: true
    port: 8088
    password: "hello-world"
    method: "aes_256_gcm"
    websocket:
      enabled: true
      port: 8089

  trojan:
    enabled: false
    port: 443
    password: "hello-world"
    mask_host: ""
    mask_port: 443
    certfile: "/path/to/cert.pem"
    keyfile: "/path/to/key.pem"
  ```
  """

  require Logger

  @doc """
  Loads configuration from YAML file and returns parsed config map.

  Returns `{:ok, config}` on success, or `{:error, reason}` on failure.

  ## Options

  - `:config_file` - Path to YAML config file (default: from `CONFIG_FILE` env var or `config/stealth.yml`)

  ## Examples

      iex> Stealth.ConfigLoader.load_config()
      {:ok, %{"shadowsocks" => %{"enabled" => true, ...}}}

      iex> Stealth.ConfigLoader.load_config(config_file: "/path/to/config.yml")
      {:ok, %{"shadowsocks" => %{...}}}
  """
  def load_config(opts \\ []) do
    config_file = opts[:config_file] || default_config_path()

    case File.exists?(config_file) do
      true ->
        Logger.info("Loading configuration from: #{config_file}")
        parse_yaml_file(config_file)

      false ->
        Logger.debug("YAML config file not found: #{config_file}")
        {:error, :file_not_found}
    end
  end

  @doc """
  Loads YAML configuration and applies it to the application config.

  This function should be called from `config/runtime.exs` to load YAML-based
  configuration at runtime.

  Returns `:ok` if config loaded successfully, or `:skip` if no config file found.
  """
  def apply_yaml_config do
    case load_config() do
      {:ok, yaml_config} ->
        Logger.info("Applying YAML configuration")
        apply_config(yaml_config)
        :ok

      {:error, :file_not_found} ->
        Logger.debug("No YAML config file found, using environment variables")
        :skip

      {:error, reason} ->
        Logger.error("Failed to load YAML config: #{inspect(reason)}")
        :skip
    end
  end

  # Private functions

  defp default_config_path do
    System.get_env("CONFIG_FILE") || Path.join([File.cwd!(), "config", "stealth.yml"])
  end

  defp parse_yaml_file(file_path) do
    case YamlElixir.read_from_file(file_path) do
      {:ok, config} when is_map(config) ->
        {:ok, config}

      {:ok, _} ->
        {:error, :invalid_yaml_format}

      {:error, reason} ->
        Logger.error("Failed to parse YAML file: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp apply_config(yaml_config) do
    # Apply Shadowsocks configuration
    if shadowsocks_config = yaml_config["shadowsocks"] do
      apply_shadowsocks_config(shadowsocks_config)
    end

    # Apply Trojan configuration
    if trojan_config = yaml_config["trojan"] do
      apply_trojan_config(trojan_config)
    end
  end

  defp apply_shadowsocks_config(ss_config) do
    enabled = get_config_value(ss_config, "enabled", true)
    Application.put_env(:stealth, :enable_ss, enabled)

    port = get_config_value(ss_config, "port", 8088)
    password = get_config_value(ss_config, "password", "hello-world")
    method = get_config_value(ss_config, "method", "aes_256_gcm") |> to_atom_safe()

    ws_config = ss_config["websocket"] || %{}
    ws_enabled = get_config_value(ws_config, "enabled", true)
    ws_port = get_config_value(ws_config, "port", 8089)

    Application.put_env(:stealth, :ss,
      port: port,
      passwd: password,
      method: method,
      ws_enabled: ws_enabled,
      ws_port: ws_port
    )

    Logger.info(
      "Shadowsocks config: enabled=#{enabled}, port=#{port}, method=#{method}, ws_port=#{ws_port}"
    )
  end

  defp apply_trojan_config(trojan_config) do
    enabled = get_config_value(trojan_config, "enabled", false)
    Application.put_env(:stealth, :enable_trojan, enabled)

    port = get_config_value(trojan_config, "port", 443)
    password = get_config_value(trojan_config, "password", "hello-world")
    mask_host = get_config_value(trojan_config, "mask_host", "")
    mask_port = get_config_value(trojan_config, "mask_port", 443)

    # SSL certificate files (optional)
    certfile = trojan_config["certfile"]
    keyfile = trojan_config["keyfile"]

    base_config = [
      port: port,
      passwd: password,
      mask_host: mask_host,
      mask_port: mask_port
    ]

    config =
      if certfile && keyfile do
        Keyword.merge(base_config, certfile: certfile, keyfile: keyfile)
      else
        base_config
      end

    Application.put_env(:stealth, :trojan, config)

    Logger.info(
      "Trojan config: enabled=#{enabled}, port=#{port}, mask_host=#{mask_host}, certfile=#{certfile || "none"}"
    )
  end

  defp get_config_value(config, key, default) do
    case Map.get(config, key) do
      nil -> default
      value -> value
    end
  end

  defp to_atom_safe(value) when is_binary(value) do
    String.to_atom(value)
  end

  defp to_atom_safe(value) when is_atom(value) do
    value
  end
end
