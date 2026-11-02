#!/bin/sh
# r12-sync.sh -- copy the workspace tree to the Mac build directory.
#
# WHY A SCRIPT
# ------------
# The Mac is where the kext builds (it has the SDK and the toolchain); Windows
# is where the sources are edited. Every round spends a dozen manual scp calls
# on this, and each one is a chance to build a stale tree and then believe the
# result. One command, one tar stream, and the receiving side starts from an
# empty directory so a deleted file cannot linger.
#
# It is deliberately NOT rsync: the Windows OpenSSH here has no rsync, and
# "delete everything then extract" is the property that matters.
set -eu
cd "$(dirname "$0")/.."
MAC=${MAC:-ling@192.168.50.204}
DEST=${DEST:-r12work}

ssh -o BatchMode=yes "$MAC" "rm -rf ~/$DEST && mkdir -p ~/$DEST"
tar -czf - kext tools tests src include fixtures docs 2>/dev/null |
    ssh -o BatchMode=yes "$MAC" "tar -xzf - -C ~/$DEST"
# WHY THE chmod IS HERE
# ---------------------
# The source tree lives on a Windows volume whose directory modes tar carries
# across as 0555. The first sync of this round produced a tree where `rm -rf`
# could not delete anything and a second sync silently kept the OLD files --
# which is exactly the "built a stale tree and believed the result" failure
# this script exists to prevent. Making the copy writable is part of copying.
ssh -o BatchMode=yes "$MAC" "chmod -R u+rwX ~/$DEST && cd ~/$DEST && \
    echo synced: \$(find . -name '*.hpp' -o -name '*.cpp' | wc -l | tr -d ' ') sources"
