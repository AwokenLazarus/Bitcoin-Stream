# Updating

"Upstream" is the xbt-rs workspace itself: the six images `scripts/oci_build.sh --load` makes and loads as
`<image>:<version>` (`startos/spec.ts`, `IMAGES`). There is no external image to track.

## A new xbt-rs version

1. Bump `version` in the workspace `Cargo.toml`; `scripts/oci_build.sh --load` then tags the images with it.
2. Set the same tag in `startos/spec.ts` (`IMAGES`) and in `packaging/umbrel/*/docker-compose.yml`.
3. Add a `startos/versions/v<version>.ts` with release notes (and a migration if the data layout changed:
   docs/CONTAINER.md is the contract), make it `current`, and move the old one to `other`.
4. `packaging/startos/test-startos.sh` (build, inspect, regtest), then side-load.
