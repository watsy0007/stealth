import Config

config :logger, :console,
  level: :info,
  format: "$time $message $metadata"
