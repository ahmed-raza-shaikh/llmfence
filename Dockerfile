FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/llmfence /usr/local/bin/llmfence
COPY policy.example.toml /etc/gateway/policy.toml
ENV LLMFENCE_LISTEN=0.0.0.0:8080 \
    LLMFENCE_POLICY=/etc/gateway/policy.toml
EXPOSE 8080
ENTRYPOINT ["llmfence", "serve"]
