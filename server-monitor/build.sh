#!/usr/bin/env bash
# Cross-compile server-monitor for the usual server targets.
#
# CGO is off and the module has no dependencies, so the results are static
# binaries that run on any Linux of the right architecture — no glibc version
# to match, nothing to install on the server.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p dist

VERSION=$(grep -oE 'version = "[^"]+"' main.go | head -1 | cut -d'"' -f2)

for target in linux/amd64 linux/arm64 linux/arm darwin/arm64; do
    goos=${target%/*}
    goarch=${target#*/}
    out="dist/server-monitor-${goos}-${goarch}"
    echo "building $out"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -trimpath -ldflags "-s -w" -o "$out" .
done

echo
echo "server-monitor $VERSION"
ls -lh dist/
echo
cat <<'EOT'
copy to a server with:
  scp dist/server-monitor-linux-amd64 root@HOST:/usr/local/bin/server-monitor
  scp skywire-monitor.service          root@HOST:/etc/systemd/system/

then either run it interactively:
  sudo server-monitor watch -duration 6h

or, for anything unattended, as a service (survives ssh drops and reboots):
  systemctl daemon-reload && systemctl enable --now skywire-monitor
  journalctl -u skywire-monitor -f
EOT
