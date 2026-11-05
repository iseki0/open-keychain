#!/usr/bin/env bash
set -euo pipefail

# Prerequisites: Go >=1.27.3, JDK17+, Android SDK, and NDK28.2.13676358.
# ANDROID_HOME and ANDROID_NDK_HOME may select locally installed SDK/NDK paths.
# Build from any working directory. No SDKs or toolchains are downloaded here.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
bridge_dir="$script_dir/tailscale"
: "${ANDROID_HOME:?Set ANDROID_HOME to an Android SDK directory}"
: "${ANDROID_NDK_HOME:=$ANDROID_HOME/ndk/28.2.13676358}"
export ANDROID_NDK_HOME
if [[ -n "${JAVA_HOME:-}" ]]; then
  export PATH="$JAVA_HOME/bin:$PATH"
fi
if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
  echo "Missing Android NDK: $ANDROID_NDK_HOME" >&2
  exit 1
fi

# Keep build tool installation separate from the module and user's GOPATH/bin.
tools_dir="${TAILAGENT_TOOLS_DIR:-$bridge_dir/.tools}"
mkdir -p "$tools_dir"
export PATH="$tools_dir:$PATH"
mobile_version="v0.0.0-20261011034528-197770444867"
GOBIN="$tools_dir" go install "golang.org/x/mobile/cmd/gomobile@$mobile_version"
GOBIN="$tools_dir" go install "golang.org/x/mobile/cmd/gobind@$mobile_version"
gomobile init
cd "$bridge_dir"
go mod download
gomobile bind -trimpath -ldflags='-s -w' -target=android/arm64,android/arm,android/amd64 -androidapi 24 -o tailagent.aar .
