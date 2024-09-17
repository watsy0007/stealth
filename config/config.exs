import Config

config :stealth, ss_port: 8088
config :stealth, ss_password: "hello-world"
config :stealth, ss_method: :aes_256_gcm

import_config "#{config_env()}.exs"
