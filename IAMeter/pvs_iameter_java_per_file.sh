#!/usr/bin/env sh
# Run PVS-Studio Java on each IAMeter benchmark .java file separately, then merge JSON.
#
# Prerequisites:
#   - mvn, java on PATH; ``mvn compile`` in IAMeter_Java
#   - PVS-Studio Java core: pvs-studio.jar (set PVS_STUDIO_JAR or install under
#     ~/.config/PVS-Studio-Java/<ver>/pvs-studio.jar on Linux/macOS)
#   - License: as for normal PVS (global.json in ~/.config/PVS-Studio-Java/ or
#     pass extra flags via PVS_EXTRA_ARGS, e.g. -a "--license-path /path/PVS-Studio.lic")
#
# Usage (from repository root):
#   sh compsast-artifacts/pvs_iameter_java_per_file.sh
#
# Outputs:
#   IAMeter_Java/pvs-by-file/<class>.json   — one report per file
#   IAMeter_Java/pvs_project_report_per_file.json  — merged (used by iometer_sarif_score if present)
#
# Doc: https://pvs-studio.com/en/docs/manual/6703/  (-s for source files, --ext-file for classpath)
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJ="${ROOT}/IAMeter_Java"
JAR="${PVS_STUDIO_JAR:-}"
if [ -z "$JAR" ] && command -v ls >/dev/null 2>&1; then
  # ${APPDATA:+-...} omits the token when APPDATA is unset (needed with set -u; macOS has no APPDATA)
  for d in "$HOME/.config/PVS-Studio-Java" "$HOME/Library/Application Support/PVS-Studio-Java" ${APPDATA:+"$APPDATA/PVS-Studio-Java"}; do
    if [ -d "$d" ]; then
      JAR="$(find "$d" -name 'pvs-studio.jar' 2>/dev/null | head -1 || true)"
      [ -n "$JAR" ] && break
    fi
  done
fi
if [ -z "$JAR" ] || [ ! -f "$JAR" ]; then
  echo "Set PVS_STUDIO_JAR to the path of pvs-studio.jar (PVS-Studio Java core)." >&2
  echo "On macOS/Linux it is often: ~/.config/PVS-Studio-Java/<version>/pvs-studio.jar" >&2
  exit 1
fi

if [ ! -f "${PROJ}/target/pvs-cp.oneline" ]; then
  echo "Missing target/pvs-cp.oneline. Run: (cd $PROJ && mvn -q -DincludeScope=compile dependency:build-classpath -Dmdep.outputFile=target/pvs-classpath.txt && echo \"target/classes:\$(cat target/pvs-classpath.txt)\" | tr -d '\n' > target/pvs-cp.oneline)" >&2
  exit 1
fi

( cd "$PROJ" && mvn -q compile ) || { echo "mvn compile failed" >&2; exit 1; }

# pvs-cp.oneline uses relative path "target/classes:...". PVS resolves it from the process cwd,
# so the analyzer must run with cwd=IAMeter_Java (not the repo root), or you get
# "Error: target/classes does not exist".
if [ ! -d "$PROJ/target/classes" ]; then
  echo "Missing $PROJ/target/classes after compile." >&2
  exit 1
fi

OUT_DIR="${PROJ}/pvs-by-file"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

for src in "$PROJ"/src/main/java/iameter/*.java; do
  [ -f "$src" ] || continue
  base="$(basename "$src" .java)"
  out="${OUT_DIR}/${base}.json"
  echo "PVS: $base"
  # One source file at a time; same classpath as full-project runs
  # Note: do not use "echo $?" inside "if ! cmd; then" — $? there is the if-statement status, not java's.
  set +e
  ( cd "$PROJ" && java -jar "$JAR" \
    -s "$src" \
    --ext-file "target/pvs-cp.oneline" \
    -j "${PVS_THREADS:-2}" \
    -O json \
    -o "$out" )
  rc=$?
  set -e
  # PVS may return 53 when --fail-on-warnings and issues were found (still a successful run).
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 53 ]; then
    echo "WARN: PVS failed for $base (java exit $rc)" >&2
  elif [ ! -s "$out" ]; then
    echo "WARN: PVS did not create a non-empty report: $out" >&2
  fi
done

# Count real *.json (if glob matches nothing, some shells yield one non-existent path)
json_n=0
for j in "$OUT_DIR"/*.json; do
  [ -f "$j" ] || continue
  json_n=$((json_n + 1))
done
if [ "$json_n" -eq 0 ]; then
  echo "No per-file PVS JSON in $OUT_DIR; skip merge. Fix PVS output or license, then re-run." >&2
  exit 1
fi

python3 "$ROOT/compsast-artifacts/merge_pvs_json_reports.py" --from-dir "$OUT_DIR" -o "$PROJ/pvs_project_report_per_file.json"
echo "Merged -> ${PROJ}/pvs_project_report_per_file.json"
echo "The scoring script uses this file if it exists; otherwise pvs_project_report.json."
