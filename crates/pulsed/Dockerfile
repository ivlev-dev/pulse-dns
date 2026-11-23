# syntax=docker/dockerfile:1
FROM rust:1.99-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p pulsed

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/pulsed /usr/local/bin/pulsed
COPY examples/zones.json /etc/pulse/zones.json
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/pulsed"]
CMD ["--config", "/etc/pulse/zones.json", "--listen-udp", "0.0.0.0:5353", "--listen-tcp", "0.0.0.0:5353"]
