import Config

config :stealth, :ss,
  port: 8088,
  passwd: "hello-world",
  method: :aes_256_gcm

config :stealth, :trojan,
  port: 443,
  passwd: "hello-world"

import_config "#{config_env()}.exs"
