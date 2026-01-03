# Start required applications for tests
Application.ensure_all_started(:telemetry)
Application.ensure_all_started(:cachex)

# Start mock HTTP server for tests
{:ok, _pid} = MockHTTPServer.start_link(port: 18080)

# Configure ExUnit to capture logs by default
# This suppresses log output during tests while still allowing logging in production code
ExUnit.start(capture_log: true)
