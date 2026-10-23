# Build from the repository root:
#   docker build -f deploy/Dockerfile -t remoteconn-server .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p rc-server

FROM debian:bookworm-slim
RUN useradd --system --home /data remoteconn && mkdir -p /data && chown remoteconn /data
COPY --from=build /src/target/release/rc-server /usr/local/bin/rc-server
USER remoteconn
# The admin panel listens on all interfaces inside the container only: publish
# it on the host's loopback (127.0.0.1:8080:8080), never publicly.
ENV RC_BIND=0.0.0.0:21116 RC_DATA_DIR=/data RC_ADMIN_BIND=0.0.0.0:8080 RUST_LOG=info
VOLUME /data
EXPOSE 21116/udp 8080/tcp
ENTRYPOINT ["rc-server"]
