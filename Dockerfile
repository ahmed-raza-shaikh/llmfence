FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/ai-governance-gateway /usr/local/bin/ai-governance-gateway
COPY policy.example.toml /etc/gateway/policy.toml
ENV GATEWAY_LISTEN=0.0.0.0:8080 \
    GATEWAY_POLICY=/etc/gateway/policy.toml
EXPOSE 8080
ENTRYPOINT ["ai-governance-gateway", "serve"]
