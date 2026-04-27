#!/usr/bin/env sh
# Run Joern Scan on IAMeter_Go, IAMeter_Java, IAMeter_PHP (three separate invocations;
# one language per project — joern-scan does not mix languages in a single run).
#
# Prerequisite: `joern-scan` on PATH (install Joern: https://docs.joern.io/installation ).
# See languages:  joern-scan --list-languages
#
# Usage (from repository root):
#   sh help-tools/joern_iameter_all.sh
#
# Outputs (text, Joern "Result: ..." lines) are saved next to each project as joern-scan.txt
# (stdout/stderr of joern-scan). If python3 is available, also runs joern_scan_txt_to_sarif.py
# to create IAMeter_*/joern-scan.sarif.
#
# Notes:
#   - Java: run after `mvn -q compile` so bytecode/classpath exist for the `java` CPG mode.
#   - Go: if scan fails, ensure `go mod tidy` / build works in IAMeter_Go.
#   - Some Joern / Homebrew setups need symlinks for go/php frontends; see Joern "Common issues".
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
J="${JOERN_SCAN:-joern-scan}"
if ! command -v "$J" >/dev/null 2>&1; then
  echo "Not found: $J. Install Joern and ensure joern-scan is on PATH, or set JOERN_SCAN=/path/to/joern-scan" >&2
  exit 1
fi

# Optional: fresh query database (slow, use when queries were updated)
# "$J" --updatedb

run_scan() {
  _label="$1"
  _dir="$2"
  shift 2
  echo "========== $_label ==========" >&2
  (
    cd "$_dir" || exit 1
    # shellcheck disable=SC2086
    "$J" --overwrite . "$@" 2>&1 | tee joern-scan.txt
  ) || true
  echo "" >&2
}

# Language flags: must match `joern-scan --list-languages` on your install (often lower case).
# Override if needed:  JOERN_LANG_GO=golang  JOERN_LANG_JAVA=java  sh help-tools/...

: "${JOERN_LANG_GO:=golang}"
: "${JOERN_LANG_JAVA:=java}"
: "${JOERN_LANG_PHP:=php}"

run_scan "IAMeter_Go" "$ROOT/IAMeter_Go" --language "$JOERN_LANG_GO"

( cd "$ROOT/IAMeter_Java" && mvn -q compile ) || {
  echo "mvn compile failed in IAMeter_Java; Java joern-scan may be empty" >&2
}
run_scan "IAMeter_Java" "$ROOT/IAMeter_Java" --language "$JOERN_LANG_JAVA"

run_scan "IAMeter_PHP" "$ROOT/IAMeter_PHP" --language "$JOERN_LANG_PHP"

echo "Done. Text logs: IAMeter_*/joern-scan.txt" >&2
if command -v python3 >/dev/null 2>&1; then
  python3 "$ROOT/help-tools/joern_scan_txt_to_sarif.py" --root "$ROOT" && echo "SARIF: IAMeter_*/joern-scan.sarif" >&2
fi
echo "If a language name fails, run:  joern-scan --list-languages" >&2
