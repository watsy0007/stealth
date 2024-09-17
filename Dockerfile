FROM elixir:1.17.2-otp-27-slim AS build

ENV MIX_ENV=prod

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates
RUN mix local.hex --force && \
    mix hex.config unsafe_https true && \
    mix local.rebar --force

COPY mix.exs mix.lock ./
COPY config config
RUN mix do deps.get, deps.compile

COPY . .

RUN mix do compile, release

FROM elixir:otp-27-slim AS app

WORKDIR /app
ENV HOME=/app \
    LANG=C.UTF-8

COPY --from=build /build/_build/prod/rel/stealth ./

CMD ["/app/bin/stealth", "start"]
