#!/usr/bin/env bash
# Prove the built image actually works, rather than merely building.
#
#   docker build -t unifi-support-file-analyzer:test .
#   docker/smoke-test.sh unifi-support-file-analyzer:test
#
# Four things are checked, because these are the four that a change to the
# Dockerfile or the entrypoint can quietly break while the image still builds:
# the server answers, a support file left in the import directory is picked up,
# clearing storage on start-up really empties it, and turning that off really
# keeps it. The process is also confirmed not to be running as root.
set -euo pipefail

IMAGE="${1:-unifi-support-file-analyzer:test}"
PORT="${SMOKE_PORT:-18077}"
NAME="analyzer-smoke-$$"
WORK="$(mktemp -d)"
BUNDLE="support-EXAMPLE-0000000000"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    # The container writes into $WORK as its own user, which may not be this
    # one, so hand the tree back before removing it. --entrypoint goes straight
    # to chown as root rather than through the start-up script.
    docker run --rm -v "$WORK:/w" --entrypoint chown "$IMAGE" \
        -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL  $1" >&2
    echo "--- container log ---" >&2
    docker logs "$NAME" 2>&1 | tail -40 >&2 || true
    exit 1
}

pass() { echo "PASS  $1"; }

start() {
    local clear_on_start="$1"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" \
        -p "127.0.0.1:${PORT}:8077" \
        -e PUID="$(id -u)" \
        -e PGID="$(id -g)" \
        -e ANALYZER_CLEAR_ON_START="$clear_on_start" \
        -v "$WORK/data:/data" \
        -v "$WORK/import:/import:ro" \
        "$IMAGE" >/dev/null
}

wait_ready() {
    for _ in $(seq 1 60); do
        if curl -fsS "http://127.0.0.1:${PORT}/api/bundles" >/dev/null 2>&1; then
            return 0
        fi
        docker inspect -f '{{.State.Running}}' "$NAME" | grep -q true \
            || fail "container exited before answering"
        sleep 1
    done
    fail "server did not answer within 60 seconds"
}

bundles() { curl -fsS "http://127.0.0.1:${PORT}/api/bundles"; }

# A support file only has to be a readable tar for the import path to be
# exercised; what is inside it is the analysis code's business, not the
# container's.
mkdir -p "$WORK/import" "$WORK/data" "$WORK/src/$BUNDLE/system"
echo "hardware model: EXAMPLE" > "$WORK/src/$BUNDLE/system/info.txt"
tar czf "$WORK/import/${BUNDLE}.tgz" -C "$WORK/src" "$BUNDLE"

echo "== first start, clearing on =="
start true
wait_ready
pass "server answers on http://127.0.0.1:${PORT}"

version_json="$(curl -fsS "http://127.0.0.1:${PORT}/api/version")" \
    || fail "/api/version did not answer"
pass "reports version $(printf '%s' "$version_json" \
    | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"

# The firmware manifest is a data file rather than code, which makes it exactly
# the sort of thing an ignore rule drops from the image while everything still
# builds and starts. It nearly was: .gitignore's rule for the bundle workspace
# matched analyzer/data/ too. Without the manifest the process audit compares
# against nothing and reports every process on the device as not shipped, so
# its absence has to be a failure here rather than a surprise later.
printf '%s' "$version_json" | grep -q '"available":true' \
    || fail "the firmware manifest is missing from the image"
pass "firmware manifest shipped in the image"

bundles | grep -q "$BUNDLE" || fail "the file in /import was not imported"
pass "support file in /import was imported"

owner="$(docker exec "$NAME" stat -c '%u' /proc/1)"
[ "$owner" != "0" ] || fail "the server is running as root"
pass "server runs as uid $owner, not root"

echo "== restart with clearing on =="
# The import directory stays mounted, so the bundle itself is imported again on
# every start and its presence proves nothing either way. A file that nothing
# recreates is what tells the two settings apart.
docker exec "$NAME" sh -c 'echo kept > /data/uploads/marker'
docker restart "$NAME" >/dev/null
wait_ready
docker exec "$NAME" sh -c '[ ! -f /data/uploads/marker ]' \
    || fail "storage survived a restart with clearing on"
pass "storage was emptied on restart"

echo "== restart with clearing off =="
docker exec "$NAME" sh -c 'echo kept > /data/uploads/marker'
docker rm -f "$NAME" >/dev/null
start false
wait_ready
docker exec "$NAME" sh -c '[ -f /data/uploads/marker ]' \
    || fail "storage was cleared even though clearing is off"
pass "storage survived a restart with clearing off"

bundles | grep -q "$BUNDLE" || fail "bundle missing after restart"
pass "bundle still present"

echo
echo "All checks passed for $IMAGE"
