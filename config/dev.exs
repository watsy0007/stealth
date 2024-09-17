import Config

config :logger, :console,
  level: :debug,
  format: "$time $message $metadata"
