#!/bin/sh
# Compatibility entry point; built bundle versions follow the checked-out commit.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /bin/sh "$HERE/../r54/build.sh" "$@"
