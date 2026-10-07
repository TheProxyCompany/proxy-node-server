#!/bin/bash
# Install the pinned MIT Cua CLI into a Proxy-owned helper directory.
# No shell profile, global installation, Cua account, or host permission changes.
set -euo pipefail
if [[ $# != 1 || "$1" != /* ]]; then
  echo 'usage: install-cua-helper.sh ABSOLUTE_PROXY_HELPER_DIRECTORY' >&2
  exit 2
fi
if [[ $(uname -s) != Darwin || $(uname -m) != arm64 ]]; then
  echo 'This preview helper pin supports macOS arm64 only.' >&2
  exit 2
fi
version=0.4.1
archive_sha=9491c118246c7dd3c06a42442d463319765fc246bf94e5bee73ac08e76716428
upstream_commit=ed22ad958a5ab6d764c98261b24d65f80f3a6f95
url="https://github.com/trycua/cua/releases/download/cua-sdk-v${version}/cua-cli-${version}-darwin-arm64.tar.gz"
destination=$1
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
notice="$script_dir/../licenses/CUA-MIT.txt"
[[ -f "$notice" ]] || { echo 'Pinned Cua MIT notice is missing.' >&2; exit 1; }
umask 077
mkdir -p -- "$destination"
staging=$(mktemp -d "$destination/.cua-install.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT
if [[ -n ${PROXY_CUA_ARCHIVE:-} ]]; then
  cp -- "$PROXY_CUA_ARCHIVE" "$staging/cua.tar.gz"
else
  curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error "$url" -o "$staging/cua.tar.gz"
fi
actual_sha=$(shasum -a 256 "$staging/cua.tar.gz" | awk '{print $1}')
[[ "$actual_sha" == "$archive_sha" ]] || { echo 'Pinned Cua archive checksum mismatch.' >&2; exit 1; }
tar -xzf "$staging/cua.tar.gz" -C "$staging" cua
codesign --verify --strict "$staging/cua"
signature=$(codesign -dv --verbose=2 "$staging/cua" 2>&1)
[[ "$signature" == *'TeamIdentifier=YCK386LBJ7'* ]] || { echo 'Unexpected Cua vendor signing team.' >&2; exit 1; }
chmod 755 "$staging/cua"
cp -- "$notice" "$staging/CUA-MIT.txt"
binary_sha=$(shasum -a 256 "$staging/cua" | awk '{print $1}')
cat > "$staging/receipt.json" <<JSON
{"name":"cua-cli","version":"$version","platform":"darwin-arm64","archive_sha256":"$archive_sha","binary_sha256":"$binary_sha","upstream_commit":"$upstream_commit","signing_team":"YCK386LBJ7","license":"MIT","guest_service_license":"FSL-1.1-MIT (separately installed cua-spacesd)"}
JSON
mv -- "$staging/cua" "$destination/cua"
mv -- "$staging/CUA-MIT.txt" "$destination/CUA-MIT.txt"
mv -- "$staging/receipt.json" "$destination/receipt.json"
printf '%s\n' "$destination/cua"
