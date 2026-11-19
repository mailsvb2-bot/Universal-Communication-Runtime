#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <apt-package>..." >&2
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive

# GitHub's ephemeral Ubuntu runners occasionally expose a stale or 503ing
# mirror+file:/etc/apt/apt-mirrors.txt source. Retrying that same source
# cannot recover a missing .deb. Fail over to the official signed Ubuntu
# repositories without weakening package signature verification.
apt_opts=(
  -o Acquire::Retries=1
  -o Acquire::http::Timeout=15
  -o Acquire::https::Timeout=15
  -o Dpkg::Use-Pty=0
)

ubuntu_release="$(. /etc/os-release; printf '%s' "${VERSION_CODENAME:-}")"
if [ "$ubuntu_release" != noble ]; then
  echo "unsupported CI Ubuntu suite: $ubuntu_release" >&2
  exit 1
fi
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
if [ ! -r "$keyring" ]; then
  echo "Ubuntu archive signature keyring unavailable" >&2
  exit 1
fi

# Never mutate the system's sources. A transient isolated override applies
# only to these verified APT calls. Official HTTPS archive is preferred on
# fallback because a partial mirror+file upgrade may report HTTP 503 forever.
fallback_sources="$(mktemp)"
trap 'rm -f "$fallback_sources"' EXIT
cat > "$fallback_sources" <<SOURCES
deb [signed-by=$keyring] https://archive.ubuntu.com/ubuntu $ubuntu_release main restricted universe multiverse
deb [signed-by=$keyring] https://archive.ubuntu.com/ubuntu $ubuntu_release-updates main restricted universe multiverse
deb [signed-by=$keyring] https://security.ubuntu.com/ubuntu $ubuntu_release-security main restricted universe multiverse
SOURCES

run_apt() {
  local label="$1"
  shift
  local -a options=("${apt_opts[@]}")
  if [ "$label" = official ]; then
    options+=(
      -o "Dir::Etc::sourcelist=$fallback_sources"
      -o Dir::Etc::sourceparts=-
      -o APT::Get::List-Cleanup=0
    )
  fi
  echo "apt install source=$label: $*" >&2
  sudo timeout 75s apt-get "${options[@]}" update -qq &&
    sudo timeout 110s apt-get "${options[@]}" install -y --no-install-recommends "$@"
}

# Try the runner-provided sources once. On package 503, redirect all later
# update/install traffic to official signed sources, not the broken mirror.
if run_apt runner "$@"; then
  exit 0
fi
echo "runner APT mirror unavailable; falling back to signed official Ubuntu sources" >&2
sudo timeout 30s dpkg --configure -a >/dev/null 2>&1 || true
for attempt in 1 2; do
  echo "official Ubuntu APT fallback attempt $attempt/2" >&2
  if run_apt official "$@"; then
    exit 0
  fi
  sudo timeout 30s dpkg --configure -a >/dev/null 2>&1 || true
  if [ "$attempt" -lt 2 ]; then sleep 5; fi
done

echo "apt install failed on runner and official signed Ubuntu sources: $*" >&2
exit 1
