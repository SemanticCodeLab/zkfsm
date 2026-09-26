# syntax=docker/dockerfile:1
# Multi-stage build: pinned Zig toolchain -> static musl binary -> minimal runtime.
# The builder always runs natively and cross-compiles for TARGETARCH.

FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS zig
ARG ZIG_VERSION=0.15.2
ARG ZIG_SHA256_AMD64=02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239
ARG ZIG_SHA256_ARM64=958ed7d1e00d0ea76590d27666efbf7a932281b3d7ba0c6b01b0ff26498f667f
ARG BUILDARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "$BUILDARCH" in \
      amd64) arch=x86_64; sum="$ZIG_SHA256_AMD64" ;; \
      arm64) arch=aarch64; sum="$ZIG_SHA256_ARM64" ;; \
      *) echo "unsupported build arch $BUILDARCH" >&2; exit 1 ;; \
    esac; \
    name="zig-${arch}-linux-${ZIG_VERSION}"; \
    curl -fsSLo /tmp/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/${name}.tar.xz"; \
    echo "${sum}  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/zig && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    rm /tmp/zig.tar.xz
ENV PATH=/opt/zig:$PATH

FROM zig AS build
ARG TARGETARCH
WORKDIR /src
COPY build.zig build.zig.zon ./
COPY src ./src
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) t=x86_64-linux-musl ;; \
      arm64) t=aarch64-linux-musl ;; \
      *) echo "unsupported target arch $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    zig build -Dtarget="$t" -Doptimize=ReleaseSafe --prefix /out; \
    mkdir -p /rootfs/data /rootfs/tmp; \
    chown 10001:10001 /rootfs/data; chmod 1777 /rootfs/tmp

# Static busybox gives the healthcheck an HTTP client; the runtime has no shell otherwise.
FROM busybox:1.36-musl AS busybox

FROM scratch
COPY --from=build /rootfs/ /
COPY --from=build /out/bin/zkfsm /usr/local/bin/zkfsm
COPY --from=busybox /bin/busybox /usr/local/bin/busybox
USER 10001:10001
ENV ZKFSM_DATA=/data
VOLUME ["/data"]
EXPOSE 9000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/busybox", "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:9000/health/ready"]
ENTRYPOINT ["/usr/local/bin/zkfsm"]
CMD ["--data", "/data", "--listen", "0.0.0.0:9000"]
