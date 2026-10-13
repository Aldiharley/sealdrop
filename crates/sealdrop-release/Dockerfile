FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p sealdrop-release
FROM debian:bookworm-slim
RUN useradd -r -u 10001 sealdrop && mkdir /data && chown sealdrop /data
COPY --from=build /src/target/release/sealdrop-release /usr/local/bin/
USER sealdrop
WORKDIR /data
EXPOSE 8787
ENTRYPOINT ["sealdrop-release"]
CMD ["serve", "--listen", "0.0.0.0:8787", "--db", "/data/releases.db", "--dir", "/data"]
