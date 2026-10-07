#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <apt-package>..." >&2
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive

apt_opts=(
  -o Acquire::Retries=3
  -o Acquire::http::Timeout=20
  -o Acquire::https::Timeout=20
  -o Dpkg::Use-Pty=0
)

for attempt in 1 2 3; do
  echo "apt install attempt $attempt/3: $*" >&2
  if sudo timeout 120s apt-get "${apt_opts[@]}" update -qq &&
     sudo timeout 180s apt-get "${apt_opts[@]}" install -y --no-install-recommends "$@"; then
    exit 0
  fi

  echo "apt install attempt $attempt failed" >&2
  sudo timeout 30s dpkg --configure -a >/dev/null 2>&1 || true
  if [ "$attempt" -lt 3 ]; then
    sleep $((attempt * 5))
  fi
done

echo "apt install failed after bounded retries: $*" >&2
exit 1
