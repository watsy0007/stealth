import Config

config :stealth, ss_port: System.get_env("SS_PORT", "8088") |> String.to_integer()
config :stealth, ss_password: System.get_env("SS_PASSWORD", "hello-world")
config :stealth, ss_method: System.get_env("SS_METHOD", "aes_256_gcm") |> String.to_atom()
