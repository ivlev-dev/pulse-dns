# syntax=docker/dockerfile:1
FROM rust:1.99-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p pulsed
COPY examples ./examples
RUN ./target/release/pulsed import --data /src/zones.pulse \
    --origin example.com. examples/example.com.zone \
    && chmod 0666 /src/zones.pulse

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/pulsed /usr/local/bin/pulsed
COPY examples/pulsed.json /etc/pulse/pulsed.json
COPY --from=build /src/zones.pulse /tmp/zones.pulse
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/pulsed"]
CMD ["--config", "/etc/pulse/pulsed.json", "--data", "/tmp/zones.pulse", "--listen-udp", "0.0.0.0:5353", "--listen-tcp", "0.0.0.0:5353"]
