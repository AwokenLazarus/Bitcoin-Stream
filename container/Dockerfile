# AGP-038: the agentpay images, one per binary, FROM scratch (docs/CONTAINER.md). AGP-040 adds the wallet UI
# (AGP-039) and xbt-init, the one-shot that fixes a bind mount's owners before the services start. AGP-043 adds
# xbt-work-relay, the blinded receipt relay of pay-with-work.
# Built by scripts/oci_build.sh with docker buildx for linux/amd64, linux/arm64 and linux/arm/v7 from the
# static musl binaries it stages under bin/<arch>/. There is no RUN, so no emulator is needed.
# Layer 1 (base.tar: passwd/group, /tmp, the /data skeleton with each component's owner) is byte-identical
# in all the images and stored once. Layer 2 is the binary.
# No `# syntax=` line: the builder's built-in frontend, nothing pulled.

ARG IMAGE=xbt-signer

FROM scratch AS base
ADD base.tar /
ENV XBT_DATA_DIR=/data XBT_MODE=production

FROM base AS xbt-signer
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-signer /usr/bin/xbt-signer
USER xbt-signer
ENTRYPOINT ["/usr/bin/xbt-signer"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 CMD ["/usr/bin/xbt-signer", "healthcheck"]

FROM base AS xbt-anchor-witness
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-anchor-witness /usr/bin/xbt-anchor-witness
USER xbt-anchor-witness
ENTRYPOINT ["/usr/bin/xbt-anchor-witness"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 CMD ["/usr/bin/xbt-anchor-witness", "healthcheck"]

FROM base AS xbt-wallet-mcp
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-wallet-mcp /usr/bin/xbt-wallet-mcp
ENV XBT_MCP_HTTP=0.0.0.0:33510
EXPOSE 33510
USER xbt-wallet-mcp
ENTRYPOINT ["/usr/bin/xbt-wallet-mcp"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 CMD ["/usr/bin/xbt-wallet-mcp", "--healthcheck"]

FROM base AS xbt402-hub
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt402-hub /usr/bin/xbt402-hub
EXPOSE 9480
USER xbt402-hub
ENTRYPOINT ["/usr/bin/xbt402-hub"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 CMD ["/usr/bin/xbt402-hub", "healthcheck"]

FROM base AS xbt-wallet-ui
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-wallet-ui /usr/bin/xbt-wallet-ui
ENV XBT_UI_BIND=0.0.0.0:8480
EXPOSE 8480
USER xbt-wallet-ui
ENTRYPOINT ["/usr/bin/xbt-wallet-ui"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 CMD ["/usr/bin/xbt-wallet-ui", "healthcheck"]

# AGP-043: the xbt-work blinded receipt relay. 9490 is the public, read-only listener; 9491 takes the Prime's pushes
# and must stay on a private network (set the relay-push-token secret, or XBT_RELAY_PUSH_ALLOW_OPEN=1 when only the
# Prime can reach it). Blobs live under /data/relay/blobs.
FROM base AS xbt-work-relay
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-work-relay /usr/bin/xbt-work-relay
ENV XBT_RELAY_BIND=0.0.0.0:9490 XBT_RELAY_PUSH_BIND=0.0.0.0:9491
EXPOSE 9490 9491
USER xbt-work-relay
ENTRYPOINT ["/usr/bin/xbt-work-relay"]
CMD ["serve"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 CMD ["/usr/bin/xbt-work-relay", "healthcheck"]

# The one image that runs as root: it exits once the data dir's owners and modes are right. Run it with
# cap_drop ALL + CHOWN, FOWNER, DAC_OVERRIDE, no network, read-only (docs/CONTAINER.md §7).
FROM base AS xbt-init
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0555 bin/${TARGETARCH}${TARGETVARIANT}/xbt-init /usr/bin/xbt-init
USER 0:0
ENTRYPOINT ["/usr/bin/xbt-init"]
CMD ["init"]
HEALTHCHECK NONE

# `--build-arg IMAGE=<name>` without `--target` builds that one image (the ARG is at the top): for a
# builder with no target option. scripts/oci_build.sh uses --target.
FROM ${IMAGE} AS selected
