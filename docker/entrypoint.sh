#!/bin/sh
# Prepare the storage directory, then start the analyzer as an ordinary user.
#
# Three things happen here that the application itself should not have to know
# about: storage is emptied if it was asked to be, the ids that own that
# storage are matched to the host's, and any support file left in the import
# directory is extracted before the server accepts requests.
set -eu

DATA_DIR="${ANALYZER_DATA_DIR:-/data}"
IMPORT_DIR="${ANALYZER_IMPORT_DIR:-/import}"
PORT="${PORT:-8077}"
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

# The server always listens on every address *inside* the container. Which
# address on the host it can be reached at is decided by the port publishing -
# `-p 127.0.0.1:8077:8077` or the ports: line in docker-compose.yml - and not
# here. Binding 127.0.0.1 inside a container would only make it unreachable.
BIND_ADDR="0.0.0.0"

is_true() {
    case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
        1 | true | yes | on) return 0 ;;
        *) return 1 ;;
    esac
}

# Run as the unprivileged user whether or not this script started as root, so
# nothing written before the server starts lands owned by root.
as_analyzer() {
    if [ "$(id -u)" = "0" ]; then
        gosu analyzer "$@"
    else
        "$@"
    fi
}

# Only ever the directories the analyzer writes, and only their contents. The
# mount point itself is left alone because removing it would break the mount,
# and anything else the host keeps in that directory is not ours to delete.
clear_storage() {
    for sub in bundles uploads exports; do
        target="$DATA_DIR/$sub"
        [ -d "$target" ] || continue
        find "$target" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    done
}

# First, because everything after it writes: a mount that cannot be written to
# should say so plainly rather than fail somewhere further down.
if ! mkdir -p "$DATA_DIR/bundles" "$DATA_DIR/uploads" "$DATA_DIR/exports" 2>/dev/null; then
    echo "Cannot write to $DATA_DIR." >&2
    echo "If the container was started with --user, whatever is mounted there" >&2
    echo "has to be writable by that user already. Otherwise leave --user off" >&2
    echo "and set PUID and PGID, and this will sort the ownership out itself." >&2
    exit 1
fi

if is_true "${ANALYZER_CLEAR_ON_START:-true}"; then
    echo "Clearing stored support files in $DATA_DIR (ANALYZER_CLEAR_ON_START)"
    clear_storage
else
    echo "Keeping stored support files in $DATA_DIR (ANALYZER_CLEAR_ON_START is off)"
fi

if [ "$(id -u)" = "0" ]; then
    # A bind-mounted directory belongs to a user on the host, and the ids are
    # what the two sides have in common. Moving the container's user onto the
    # host's ids leaves the files readable from outside as well as writable
    # from inside. -o allows an id already used by another account in the
    # image, which costs nothing here and avoids refusing to start over it.
    [ "$PGID" = "$(id -g analyzer)" ] || groupmod -o -g "$PGID" analyzer
    [ "$PUID" = "$(id -u analyzer)" ] || usermod -o -u "$PUID" analyzer
    chown -R analyzer:analyzer "$DATA_DIR"
fi

if [ -d "$IMPORT_DIR" ]; then
    as_analyzer python /app/docker/import_dir.py
fi

# Anything passed after the image name replaces the server, which is how to get
# a shell or run a one-off command in the container.
if [ "$#" -eq 0 ]; then
    set -- uvicorn analyzer.app:app --host "$BIND_ADDR" --port "$PORT"
    echo "Analyzer listening on port $PORT inside the container"
fi

if [ "$(id -u)" = "0" ]; then
    exec gosu analyzer "$@"
fi
exec "$@"
