#!/usr/bin/env bash
# shellcheck disable=SC1090
#
# Helper to export the environment variables required to run the Flask web UI
# and build introspection tooling on macOS. Source this script from your shell:
#
#   source scripts/env.darwin.sh
#
# It mirrors the manual exports documented in the project history but avoids
# repeating them for every terminal session.

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "[env.darwin] This helper is intended for macOS (Darwin) hosts." >&2
fi

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "[env.darwin] Please source this script instead of executing it." >&2
  exit 1
fi

if ! command -v brew >/dev/null 2>&1; then
  echo "[env.darwin] Homebrew is required but was not detected in PATH." >&2
  return 0 2>/dev/null || exit 0
fi

# Resolve Homebrew prefixes, falling back gracefully when libffi is keg-only.
brew_prefix=$(brew --prefix 2>/dev/null)
libffi_prefix=$(brew --prefix libffi 2>/dev/null || echo "${brew_prefix}")

prepend_path() {
  local var_name=$1
  local new_value=$2
  local current_value=${!var_name}
  if [[ -n "${current_value}" ]]; then
    export "${var_name}=${new_value}:${current_value}"
  else
    export "${var_name}=${new_value}"
  fi
}

prepend_path PKG_CONFIG_PATH "${libffi_prefix}/lib/pkgconfig"
prepend_path DYLD_FALLBACK_LIBRARY_PATH "${brew_prefix}/lib"

export GI_TYPELIB_PATH="${brew_prefix}/lib/girepository-1.0"
export FLASK_APP="webapp:create_app"

unset -f prepend_path
unset brew_prefix libffi_prefix
