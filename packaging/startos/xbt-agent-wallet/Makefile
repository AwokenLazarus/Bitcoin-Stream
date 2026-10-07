# StartOS has x86_64 and aarch64 boxes (no armv7). Build with packaging/startos/build.sh, which puts
# start-cli and the tar2sqfs shim on PATH; `make` alone works when they already are.
ARCHES := x86 arm
# overrides to s9pk.mk must precede the include statement
include node_modules/@start9labs/start-sdk/s9pk.mk
