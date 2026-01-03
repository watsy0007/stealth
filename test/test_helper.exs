# Start required applications for tests
Application.ensure_all_started(:cachex)

ExUnit.start()
