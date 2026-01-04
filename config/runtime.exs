import Config

# Try to load YAML configuration first
# If YAML config exists, it takes precedence over environment variables
# Otherwise, fall back to environment variable configuration (backward compatible)
case Code.ensure_loaded?(Stealth.ConfigLoader) && Stealth.ConfigLoader.apply_yaml_config() do
  :ok ->
    # YAML configuration loaded successfully
    :ok

  _ ->
    # No YAML config found or failed to load, use environment variables
    config :stealth,
      enable_ss: System.get_env("ENABLE_SS", "1") != "0"

    config :stealth, :ss,
      port: System.get_env("SS_PORT", "8088") |> String.to_integer(),
      passwd: System.get_env("SS_PASSWORD", "hello-world"),
      method: System.get_env("SS_METHOD", "aes_256_gcm") |> String.to_atom(),
      ws_port: System.get_env("SS_WS_PORT", "8089") |> String.to_integer(),
      ws_enabled: System.get_env("SS_WS_ENABLED", "1") != "0"

    config :stealth,
      enable_trojan: System.get_env("ENABLE_TROJAN", "0") != "0"

    config :stealth, :trojan,
      port: System.get_env("TROJAN_PORT", "443") |> String.to_integer(),
      passwd: System.get_env("TROJAN_PASSWORD", "hello-world"),
      mask_host: System.get_env("TROJAN_MASK_HOST", ""),
      mask_port: System.get_env("TROJAN_MASK_PORT", "443") |> String.to_integer()
end
