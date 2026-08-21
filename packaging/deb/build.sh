#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
    echo "usage: $0 <version> <amd64|arm64> <binary> [output-directory]" >&2
    exit 2
fi

readonly VERSION="$1"
readonly ARCHITECTURE="$2"
readonly BINARY="$3"
readonly OUTPUT_DIRECTORY="${4:-dist}"

if [[ ! "$VERSION" =~ ^[0-9][0-9A-Za-z.+:~_-]*$ ]]; then
    echo "invalid Debian package version: $VERSION" >&2
    exit 2
fi
case "$ARCHITECTURE" in
    amd64|arm64) ;;
    *)
        echo "unsupported Debian architecture: $ARCHITECTURE" >&2
        exit 2
        ;;
esac
if [[ ! -x "$BINARY" || ! -f "$BINARY" ]]; then
    echo "NestWG binary is not an executable regular file: $BINARY" >&2
    exit 2
fi
if ! command -v dpkg-deb >/dev/null; then
    echo "dpkg-deb is required to build a Debian package" >&2
    exit 2
fi

stage="$(mktemp -d)"
cleanup() {
    rm -rf -- "$stage"
}
trap cleanup EXIT INT TERM
chmod 0755 "$stage"

install -Dm755 "$BINARY" "$stage/usr/bin/nestwg"
install -Dm644 docs/nestwg.1 "$stage/usr/share/man/man1/nestwg.1"
gzip -9n "$stage/usr/share/man/man1/nestwg.1"
install -Dm644 completions/nestwg.bash "$stage/usr/share/bash-completion/completions/nestwg"
install -Dm644 completions/_nestwg "$stage/usr/share/zsh/vendor-completions/_nestwg"
install -Dm644 completions/nestwg.fish "$stage/usr/share/fish/vendor_completions.d/nestwg.fish"
install -Dm644 README.md "$stage/usr/share/doc/nestwg/README.md"
install -Dm644 CHANGELOG.md "$stage/usr/share/doc/nestwg/CHANGELOG.md"
install -Dm644 SECURITY.md "$stage/usr/share/doc/nestwg/SECURITY.md"
install -Dm644 SUPPORT.md "$stage/usr/share/doc/nestwg/SUPPORT.md"
install -Dm644 docs/architecture.md "$stage/usr/share/doc/nestwg/architecture.md"
install -Dm644 docs/configuration.md "$stage/usr/share/doc/nestwg/configuration.md"
install -Dm644 docs/supported-platforms.md "$stage/usr/share/doc/nestwg/supported-platforms.md"
install -Dm644 docs/threat-model.md "$stage/usr/share/doc/nestwg/threat-model.md"
install -Dm644 examples/mixed-chain.yaml "$stage/usr/share/doc/nestwg/examples/mixed-chain.yaml"
install -Dm644 packaging/deb/copyright "$stage/usr/share/doc/nestwg/copyright"
install -d -m755 "$stage/DEBIAN" "$OUTPUT_DIRECTORY"
sed -e "s/@VERSION@/$VERSION/g" -e "s/@ARCH@/$ARCHITECTURE/g" \
    packaging/deb/control.in >"$stage/DEBIAN/control"
chmod 0644 "$stage/DEBIAN/control"

dpkg-deb --build --root-owner-group "$stage" \
    "$OUTPUT_DIRECTORY/nestwg_${VERSION}_${ARCHITECTURE}.deb"
