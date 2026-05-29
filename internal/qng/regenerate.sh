#!/usr/bin/env bash
# Regenerate internal/qng: a vendored fork of quic-go that imports the RFC 7250
# TLS at internal/itls/tls instead of crypto/tls. See README.md.
#
# Usage: from the module root, run ./internal/qng/regenerate.sh
# Requires the quic-go version pinned in go.mod to be in the module cache
# (run `go mod download github.com/quic-go/quic-go` first if needed).
set -euo pipefail

MODROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$MODROOT"

QG=$(go list -m -f '{{.Dir}}' github.com/quic-go/quic-go)
DEST=internal/qng

echo "forking quic-go from: $QG"

# The packages the quic-go root transitively imports within its own module.
PKGS=$(go list -deps github.com/quic-go/quic-go | grep '^github.com/quic-go/quic-go')

# Preserve our additions (license stays; tests/docs we wrote are kept).
KEEP="LICENSE README.md regenerate.sh rawkey_quic_test.go anchor.go"
tmp=$(mktemp -d)
for f in $KEEP; do [ -e "$DEST/$f" ] && cp "$DEST/$f" "$tmp/"; done

rm -rf "$DEST"
mkdir -p "$DEST"

count=0
for p in $PKGS; do
  rel="${p#github.com/quic-go/quic-go}"; rel="${rel#/}"
  src="$QG/$rel"; [ -z "$rel" ] && { src="$QG"; rel="."; }
  mkdir -p "$DEST/$rel"
  for f in "$src"/*.go; do
    bn=$(basename "$f")
    case "$bn" in *_test.go) continue;; esac
    cp "$f" "$DEST/$rel/$bn"
    chmod u+w "$DEST/$rel/$bn" # module cache files are read-only
    count=$((count + 1))
  done
done
echo "copied $count files"

# Two import rewrites, on quoted import strings only (never comment URLs).
find "$DEST" -name '*.go' -print0 | xargs -0 perl -pi -e '
  s{"github\.com/quic-go/quic-go/internal/}{"github.com/tmc/go-iroh/internal/qng/internal/}g;
  s{"github\.com/quic-go/quic-go/qlogwriter/}{"github.com/tmc/go-iroh/internal/qng/qlogwriter/}g;
  s{"github\.com/quic-go/quic-go/qlogwriter"}{"github.com/tmc/go-iroh/internal/qng/qlogwriter"}g;
  s{"github\.com/quic-go/quic-go/qlog"}{"github.com/tmc/go-iroh/internal/qng/qlog"}g;
  s{"github\.com/quic-go/quic-go/quicvarint"}{"github.com/tmc/go-iroh/internal/qng/quicvarint"}g;
  s{"github\.com/quic-go/quic-go"}{"github.com/tmc/go-iroh/internal/qng"}g;
  s{"crypto/tls"}{tls "github.com/tmc/go-iroh/internal/itls/tls"}g;
'

# Restore our kept files and the upstream license.
cp "$QG/LICENSE" "$DEST/LICENSE"
for f in README.md regenerate.sh rawkey_quic_test.go; do
  [ -e "$tmp/$f" ] && cp "$tmp/$f" "$DEST/$f"
done
chmod +x "$DEST/regenerate.sh"
rm -rf "$tmp"

gofmt -w "$DEST"
echo "done; now run: go build ./... && go test ./internal/qng/"
