#!/bin/sh
# en2-run.sh -- run one experiment on the TARGET device (en2) without changing
# either end's subnet.
#
# WHY THIS EXISTS
# ---------------
# Round 10 needed the load to leave through en2 (the RTL8127 under observation)
# while the management SSH connection was on en0. The wrong way to get there is
# to change subnet masks or addresses on either end: that alters the user's real
# network, has uncontrolled side effects, and when it breaks you cannot tell
# whether the experiment or the environment is at fault. Round 10 did exactly
# that and interrupted the local network. Changing either end's subnet is
# forbidden by the task; this script never does it.
#
# The right way is to make en2 the ONLY path, temporarily, by taking the
# management interface down -- and to prove the en2 path works BEFORE doing so,
# so that a failure leaves you with a usable connection rather than a dead host.
#
# THE PROCEDURE (fixed; do not improvise around it)
# -------------------------------------------------
#   1. confirm SSH works over en2's OWN address, FROM THE OPERATOR MACHINE
#   2. SAVE the management interface's state (address, netmask, route)
#   3. bring the management (USB) interface down
#   4. run the experiment
#   5. bring the management interface back up, always -- including on failure
#   6. VERIFY it came back with its address AND its own default route
#
# WHAT ROUND 11 FIXED
# -------------------
#   E1  A failed restore printed an error and the script still exited 0. The
#       EXIT trap ran restore_mgmt with `|| true` and the `exit $rc` carried
#       only the COMMAND's status. FIX: command and restore status are tracked
#       separately, both are reported, and the exit code is the worst of them.
#
#   E2  A session that arrived on any interface other than the management one
#       was allowed to continue, including en1 and "we do not know". FIX: the
#       gate requires the session to have arrived on the TARGET interface's own
#       address specifically.
#
# WHAT ROUND 12 FIXES
# -------------------
#   E3  The management interface coming DOWN successfully but the load never
#       running exited 0. `CMD_RAN=0` with `CMD_RC=0` produced rc=0, so
#       "the experiment did not happen" was reported as success.
#
#       FIX: a load that did not run is a FAILURE (exit 1), not a zero. The
#       summary says "load status: not run" and the exit code reflects it.
#
#   E4  SIGINT/SIGTERM during the load: the trap ran the restore and then
#       `finish` exited with the command's status. If the command had been
#       interrupted after doing its work, or if the signal arrived between the
#       load and the restore, the run could report success. An interrupted
#       experiment is not a completed one.
#
#       FIX: the signal is recorded as its own state, and the exit code is
#       128+signal even when the restore succeeds. The four states -- setup,
#       load, signal, restore -- are reported separately, and the worst wins.
#
#   E5  The pre-existing network state was never saved, so "restored" meant
#       "up with some address" rather than "the same address and route as
#       before". FIX: the state is captured before the interface is touched and
#       compared after.
#
#   E6  An initial state the script cannot restore (no address, no default
#       route, an address the script would have to guess) was accepted and the
#       interface was taken down anyway. FIX: refuse BEFORE changing anything.
#
# WHAT ROUND 13 FIXES
# -------------------
#   E7  THE SIGNAL WAS LOST WHEN THE RESTORE FAILED. `finish` computed 128+N,
#       then `if [ "$RESTORE_RC" -ne 0 ] && [ "$rc" -eq 0 ]` could not override
#       it -- but the SUMMARY printed "restore status : 1" and the RESULT text
#       said "the management interface did not come back", so the reader was
#       told the restore failed and nothing about the signal. Worse, an
#       interrupted run whose restore then succeeded still had SIGNAL set, so
#       `finish` returned 128+N -- correct -- but the INT path called
#       `on_exit` a second time through the EXIT trap. Both facts are now
#       recorded independently and both are printed.
#
#   E8  THE ADMINISTRATIVE UP/DOWN STATE WAS NEVER READ. The script decided
#       "up" from `status: active`, which is a LINK state, not an
#       administrative one: an interface can be administratively UP with no
#       link, and `ifconfig up` on an already-up interface is a no-op that
#       reports success. The pre-state now records `ifconfig <if> | grep
#       'flags='`'s UP bit explicitly, and an interface that is administratively
#       DOWN but still carries an address and a default route is a state this
#       script REFUSES -- bringing it "back up" would change a state the
#       operator chose.
#
#   E9  ONLY THE ADDRESS WAS COMPARED AFTER THE RESTORE. Round 12 compared
#       `iface_inet` against the saved address and stopped there. A restore that
#       came back with a different NETMASK, or a different default GATEWAY, or
#       a default route on a different INTERFACE, passed. All four are now
#       saved and compared, and a mismatch is a restore failure.
#
#   E10 A RESTORE THAT DID NOT MATCH SAID "restored saved state" ANYWAY. The
#       retry loop returned 0 as soon as an address and a route were present;
#       the saved-value comparison happened only in the failure branch. Now the
#       comparison is the success condition, a mismatch triggers a repair
#       attempt, and if the repair does not produce the saved state the script
#       returns the restore-failed code and says so in the RESULT line.
#
# IF THE EXPERIMENT WEDGES THE HOST, RECOVERY DEPENDS ON WHETHER IT IS ALIVE
# -------------------------------------------------------------------------
# NanoKVM gives you a screen and a keyboard; it cannot revive a dead kernel.
# So look at the screen first, then choose:
#
#   A. The system still responds (screen refreshes, mouse moves, desktop or
#      login window visible). SSH may be down purely because the network is
#      misconfigured. Open a Terminal via NanoKVM and fix the network, or run
#      `sudo ifconfig <mgmt> down; sudo ifconfig <mgmt> up`. No reboot needed.
#
#   B. The kernel has stopped (panic text on screen, frozen image, dead
#      keyboard/mouse). Terminal.app CANNOT be opened -- the window server
#      depends on kernel scheduling. Force a power cycle via NanoKVM SSH: hold
#      the power button ~6 s, confirm the LED reads 1 (off), then press ~0.8 s.
#
# STEP 1 MUST BE RUN FROM THE SIDE THAT WILL CONNECT
# --------------------------------------------------
# "SSH over en2 works" is a statement about the path from the OPERATOR machine
# to the Mac, not about the Mac talking to itself. A local `ssh ling@<en2-ip>`
# on the Mac proves nothing: sshd listens on all addresses.
#
# So the intended use is:
#
#   from the OPERATOR machine (Windows):
#       ssh <mac-en2-ip> 'sh ~/r12work/tools/dev/en2-run.sh --run <cmd...>'
#
#   en2-run.sh --check              step 1 only, from the Mac (changes nothing)
#   en2-run.sh --run <cmd...>       steps 2..6 around <cmd>
#   en2-run.sh --restore            emergency: bring the mgmt iface back up
#   en2-run.sh --selftest           exercise every branch with command stubs
#
# SAFETY
# ------
# * Nothing here writes an address, a netmask or a route.
# * Step 3 is refused unless the operator's connection arrived on the TARGET
#   interface's address -- i.e. unless disabling the management interface is
#   provably safe.
# * Step 5 runs from a trap, so an interrupt or a failing command still restores
#   the management interface, and its result reaches the exit code.
set -u

TARGET_IFACE=${TARGET_IFACE:-en2}
MGMT_IFACE=${MGMT_IFACE:-en0}

# Command hooks. Overridable so --selftest can drive every branch without
# touching the real machine. Production leaves them at their defaults.
IFCONFIG=${IFCONFIG:-ifconfig}
NETSTAT=${NETSTAT:-netstat}
ROUTE=${ROUTE:-route}
SUDO=${SUDO:-sudo}
SLEEP=${SLEEP:-sleep}
IFCONFIG_LIST=${IFCONFIG_LIST:-}

# ---- THE FOUR STATES, TRACKED SEPARATELY --------------------------------
#
# Round 11 tracked two (command, restore) and still managed to report success
# when the command never ran and when a signal interrupted it. Each state is a
# distinct fact about the run and each has its own exit code:
#
#   SETUP_RC     step 2/3: saving state and taking the interface down
#   LOAD_RAN     did the load command actually execute
#   LOAD_RC      its status
#   SIGNAL       the signal that interrupted us, 0 if none
#   RESTORE_RC   step 5/6: bringing the interface back and verifying it
#
# The exit code is the worst of them, and the summary prints all of them.
SETUP_RC=0
LOAD_RAN=0
LOAD_RC=0
SIGNAL=0
RESTORE_RC=0
RESTORE_DONE=0

# Exit codes. Chosen so a caller can distinguish the cases without parsing.
EXIT_OK=0
EXIT_LOAD_NOT_RUN=1
EXIT_RESTORE_FAILED=90
# A signal exits 128+N, which is the shell convention and cannot collide with
# the load's own status for any N in 1..64.

# The saved pre-state.
#
# ROUND 13 (E8/E9): the admin state, the netmask, the gateway and the interface
# that owns the default route are all saved. Round 12 saved only the address and
# a boolean "has a default route", so a restore that came back with a different
# mask or a different gateway -- or a default route on a DIFFERENT interface --
# was reported as clean.
SAVED_ADDR=""
SAVED_NETMASK=""
SAVED_GATEWAY=""
SAVED_ROUTE_IFACE=""
SAVED_HAD_ROUTE=0
SAVED_ADMIN_UP=0
SAVED_STATE_OK=0

say() { printf '%s\n' "$*"; }
say_err() { printf '%s\n' "$*" >&2; }

die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

list_ifaces() {
    if [ -n "$IFCONFIG_LIST" ]; then
        printf '%s\n' $IFCONFIG_LIST
        return 0
    fi
    "$IFCONFIG" -l 2>/dev/null
}

iface_inet() {
    "$IFCONFIG" "$1" 2>/dev/null | awk '/inet /{print $2; exit}'
}

iface_netmask() {
    "$IFCONFIG" "$1" 2>/dev/null | awk '/inet /{print $4; exit}'
}

iface_active() {
    "$IFCONFIG" "$1" 2>/dev/null | grep -q 'status: active'
}

# Is $1 ADMINISTRATIVELY up?
#
# ROUND 13 (E8). `status: active` is the LINK state. The admin state is the
# UP flag in the interface's flags word:
#
#     en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>
#
# `UP` there means the interface is administratively enabled. That is the bit
# `ifconfig up`/`down` changes, and it is the bit a restore must put back. An
# interface that is admin-UP with no link is a normal state (cable unplugged);
# an interface that is admin-DOWN while still carrying an address is a state the
# operator chose deliberately, and this script must not "helpfully" change it.
iface_admin_up() {
    "$IFCONFIG" "$1" 2>/dev/null | awk '
        /^[^ \t].*flags=/ {
            if (match($0, /<[^>]*>/)) {
                f = substr($0, RSTART + 1, RLENGTH - 2)
                n = split(f, a, ",")
                for (i = 1; i <= n; i++) if (a[i] == "UP") { found = 1 }
            }
        }
        END { exit(found ? 0 : 1) }'
}

# The gateway and interface of $mgmt's OWN default route.
#
# ROUND 13 (E9): round 12 asked only "does a default route exist whose
# interface field is $mgmt". It never recorded WHICH gateway, so a restore that
# brought the interface back with a different gateway passed. The gateway and
# the interface are both written to stdout, tab-separated.
mgmt_default_route() {
    "$NETSTAT" -rn -f inet 2>/dev/null |
        awk -v i="$1" '$1 == "default" && $NF == i {print $2 "\t" $NF; exit}'
}

# Does $mgmt have its OWN default route?
#
# NOT `route -n get default`: that prints only the single highest-priority
# default route, which here is en2's, so en0's own default is invisible and the
# check reported failure while SSH over en0 was in fact working.
#
# `netstat -rn` lists EVERY default route, so the question becomes "does a
# default route exist whose interface field is $mgmt".
has_mgmt_default() {
    [ -n "$(mgmt_default_route "$1")" ]
}

target_ip() {
    iface_inet "$TARGET_IFACE"
}


session_local_addr() {
    printf '%s' "${SSH_CONNECTION:-}" | awk '{print $3}'
}

iface_of_addr() {
    addr=$1
    [ -n "$addr" ] || return 1
    for i in $(list_ifaces); do
        if "$IFCONFIG" "$i" 2>/dev/null | grep -q "inet $addr "; then
            printf '%s' "$i"
            return 0
        fi
    done
    return 1
}

# Does $mgmt have its OWN default route?
#
# NOT `route -n get default`: that prints only the single highest-priority
# default route, which here is en2's, so en0's own default is invisible and the
# check reported failure while SSH over en0 was in fact working.
#
# `netstat -rn` lists EVERY default route, so the question becomes "does a
# default route exist whose interface field is $mgmt".
has_mgmt_default() {
    "$NETSTAT" -rn -f inet 2>/dev/null |
        awk -v i="$1" '$1 == "default" && $NF == i {found=1} END {exit !found}'
}

# ---- E5/E6: save the pre-state, and refuse if it cannot be restored ------
#
# WHY SAVING IS NOT OPTIONAL
# --------------------------
# Round 11 checked that the interface had an address and a route AFTER the
# restore, but never recorded what they were BEFORE. So "restored" meant "up
# with an address", and an interface that came back on a different address, or
# with a different netmask, would have passed.
#
# WHY REFUSING IS NOT OPTIONAL
# ----------------------------
# If the interface has no address now, the script cannot bring it back to
# anything: it would have to guess, and DHCP renewal is not something this
# script is allowed to do. Taking it down in that state turns a working machine
# into an unreachable one. So the check happens BEFORE anything changes.
save_mgmt_state() {
    mgmt=$MGMT_IFACE
    [ -n "$mgmt" ] || { say_err "step 2: cannot determine the management interface"; return 1; }

    SAVED_ADDR=$(iface_inet "$mgmt")
    SAVED_NETMASK=$(iface_netmask "$mgmt")
    if iface_admin_up "$mgmt"; then SAVED_ADMIN_UP=1; else SAVED_ADMIN_UP=0; fi
    route=$(mgmt_default_route "$mgmt")
    if [ -n "$route" ]; then
        SAVED_HAD_ROUTE=1
        SAVED_GATEWAY=$(printf '%s' "$route" | cut -f1)
        SAVED_ROUTE_IFACE=$(printf '%s' "$route" | cut -f2)
    else
        SAVED_HAD_ROUTE=0
        SAVED_GATEWAY=""
        SAVED_ROUTE_IFACE=""
    fi

    say "step 2: saving $mgmt state"
    say "  admin up : ${SAVED_ADMIN_UP}"
    say "  address  : ${SAVED_ADDR:-<none>}"
    say "  netmask  : ${SAVED_NETMASK:-<none>}"
    say "  default  : ${SAVED_HAD_ROUTE}  gateway=${SAVED_GATEWAY:-<none>} iface=${SAVED_ROUTE_IFACE:-<none>}"

    if [ -z "$SAVED_ADDR" ]; then
        say_err "step 2 REFUSED: $mgmt has no IPv4 address."
        say_err "  This script restores an address it SAVED; it does not create"
        say_err "  one. Taking $mgmt down now would leave the machine reachable"
        say_err "  only through $TARGET_IFACE, and the script could not bring"
        say_err "  $mgmt back. Renew DHCP on $mgmt first, then re-run."
        return 1
    fi
    if [ "$SAVED_HAD_ROUTE" != "1" ]; then
        say_err "step 2 REFUSED: $mgmt has no default route of its own."
        say_err "  Without one, bringing it back up would not restore the"
        say_err "  operator's path, and 'restored' would be a lie. Fix the"
        say_err "  route on $mgmt first, then re-run."
        return 1
    fi
    # ROUND 13 (E8): an interface that is ADMINISTRATIVELY DOWN but still
    # carries an address and a default route is a state someone chose on
    # purpose (a spare link kept configured but disabled). This script's whole
    # premise is "take it down, then put it back". For an interface that is
    # already down, "put it back" would mean bringing it UP -- a change the
    # operator did not ask for. Refusing is the only safe answer, and it happens
    # BEFORE anything is touched.
    if [ "$SAVED_ADMIN_UP" != "1" ]; then
        say_err "step 2 REFUSED: $mgmt is administratively DOWN but still has"
        say_err "  an address ($SAVED_ADDR) and a default route"
        say_err "  ($SAVED_GATEWAY via $SAVED_ROUTE_IFACE)."
        say_err "  That is a state someone configured deliberately. Bringing it"
        say_err "  back 'up' after the experiment would CHANGE it, and leaving"
        say_err "  it down would not restore anything. This script does not"
        say_err "  guess which one you meant; fix $mgmt by hand first."
        return 1
    fi
    # The netmask is what a restore must put back too; a missing one means the
    # interface is not in a state this script can reproduce.
    if [ -z "$SAVED_NETMASK" ]; then
        say_err "step 2 REFUSED: $mgmt has an address but no netmask in the"
        say_err "  ifconfig output, so the saved state is incomplete."
        return 1
    fi
    SAVED_STATE_OK=1
    return 0
}

# ---- step 5/6: restore, and VERIFY the state came back ------------------
#
# WHY `ifconfig up` ALONE IS NOT ENOUGH
# -------------------------------------
# Measured during this procedure's own validation: after `ifconfig en0 down`
# followed by `ifconfig en0 up`, en0 came back with its address AND
# `status: active`, but WITHOUT a default route. `route -n get <peer>` still
# resolved through en2, so SSH to the en0 address timed out even though
# everything "looked" up. A second down/up cycle restored the route.
#
# So the check is about the ROUTE, and about the SAVED VALUES.
restore_mgmt() {
    mgmt=$MGMT_IFACE
    [ -n "$mgmt" ] || { say_err "step 5: cannot determine the management interface"; return 1; }

    if iface_admin_up "$mgmt"; then
        say "step 5: $mgmt reports administratively up"
    else
        say "step 5: bringing $mgmt up"
        $SUDO "$IFCONFIG" "$mgmt" up || say_err "step 5: ifconfig up FAILED"
        $SLEEP 2
    fi

    # ROUND 13 (E9/E10): SUCCESS MEANS "THE SAVED STATE", NOT "SOME STATE".
    #
    # Round 12 returned 0 as soon as the interface had an address and a default
    # route, and only compared the address in the branch that had already
    # decided to fail. So a restore that came back on a different netmask, or
    # with a different gateway, or with the default route on a different
    # interface, was reported as clean.
    #
    # Here the comparison IS the success condition. A mismatch is not a reason
    # to report success with a caveat; it is a reason to try to repair, and if
    # the repair does not produce the saved state, to fail.
    i=0
    while [ "$i" -lt 3 ]; do
        i=$((i + 1))
        mismatch=$(state_mismatch "$mgmt")
        if [ -z "$mismatch" ]; then
            say "step 5: $mgmt restored to its saved state (attempt $i)"
            say "         address=$SAVED_ADDR netmask=$SAVED_NETMASK"
            say "         default=$SAVED_GATEWAY via $SAVED_ROUTE_IFACE"
            return 0
        fi
        say "step 5: attempt $i -- $mgmt not in its saved state: $mismatch"
        if [ "$i" -lt 3 ]; then
            say "step 5: cycling $mgmt to repair"
            $SUDO "$IFCONFIG" "$mgmt" down 2>/dev/null || true
            $SLEEP 1
            $SUDO "$IFCONFIG" "$mgmt" up 2>/dev/null || true
            $SLEEP 3
        fi
    done

    say_err "step 5: $mgmt is NOT in its saved state after 3 attempts"
    say_err "        saved: address=$SAVED_ADDR netmask=$SAVED_NETMASK"
    say_err "               default=$SAVED_GATEWAY via $SAVED_ROUTE_IFACE"
    say_err "        now  : address=$(iface_inet "$mgmt") netmask=$(iface_netmask "$mgmt")"
    say_err "               default=$(mgmt_default_route "$mgmt")"
    say_err "        RECOVER MANUALLY: renew DHCP on $mgmt, or restore the"
    say_err "        route by hand. This run is NOT clean."
    say_err "        If SSH is still reachable the system is alive: fix it from a"
    say_err "        NanoKVM Terminal. If the screen shows a panic or is frozen,"
    say_err "        power-cycle via NanoKVM instead (Terminal cannot open)."
    return 1
}

# Compare the CURRENT state of $1 against the SAVED state.
#
# Prints an empty string when they match, or a short reason when they do not.
# ROUND 13 (E9): all four saved facts are compared -- admin state, address,
# netmask, and the default route's gateway AND interface. Round 12 compared the
# address only.
state_mismatch() {
    _m=$1
    _why=""
    if ! iface_admin_up "$_m"; then
        _why="administratively down"
    fi
    _a=$(iface_inet "$_m")
    if [ "$_a" != "$SAVED_ADDR" ]; then
        _why="${_why}${_why:+, }address=$_a (saved $SAVED_ADDR)"
    fi
    _n=$(iface_netmask "$_m")
    if [ "$_n" != "$SAVED_NETMASK" ]; then
        _why="${_why}${_why:+, }netmask=$_n (saved $SAVED_NETMASK)"
    fi
    _r=$(mgmt_default_route "$_m")
    _g=$(printf '%s' "$_r" | cut -f1)
    _ri=$(printf '%s' "$_r" | cut -f2)
    if [ "$_g" != "$SAVED_GATEWAY" ]; then
        _why="${_why}${_why:+, }gateway=${_g:-<none>} (saved ${SAVED_GATEWAY:-<none>})"
    fi
    if [ "$_ri" != "$SAVED_ROUTE_IFACE" ]; then
        _why="${_why}${_why:+, }default-iface=${_ri:-<none>} (saved ${SAVED_ROUTE_IFACE:-<none>})"
    fi
    printf '%s' "$_why"
}

# The trap runs on normal exit AND on INT/TERM. It records the restore result
# instead of discarding it.
on_exit() {
    [ "$RESTORE_DONE" -eq 0 ] || return 0
    RESTORE_DONE=1
    say ""
    say "step 5: restoring $MGMT_IFACE"
    if restore_mgmt; then
        RESTORE_RC=0
    else
        RESTORE_RC=1
    fi
}

# E4: a signal is its own state. It is recorded here, once, and it outranks a
# successful load because an interrupted experiment did not complete.
#
# ROUND 13 (E7): the signal must survive a FAILED restore too.
#
# Round 12's `finish` computed 128+N first and then only replaced `rc` with 90
# if `rc` was still 0 -- so a signal followed by a failed restore exited 128+N
# and the RESULT text talked only about the restore. Two different facts, one
# slot. Now both are recorded, both are printed, and the exit code is:
#
#     restore failed           -> 90   (the machine is not in its normal state;
#                                      that outranks "the run was interrupted")
#     interrupted, link ok     -> 128+N
#
# 90 is chosen over 128+N because a caller that sees 90 must go fix the host,
# and a caller that sees 128+N knows the host is fine and the run was cut short.
# The SIGNAL is still printed in the summary, so nothing is lost.
on_signal() {
    sig=$1
    if [ "$SIGNAL" -eq 0 ]; then
        SIGNAL=$sig
    fi
    say_err ""
    say_err "INTERRUPTED by SIG$sig during the experiment."
    on_exit
    finish
}

finish() {
    # THE EXIT CODE IS THE WORST OF THE FOUR STATES.
    #
    # Round 11 computed it from the command and the restore only, so:
    #   * setup failing but the command succeeding -> 0
    #   * the load never running -> 0
    #   * a signal arriving after the load's work but before the restore -> 0
    # Each of those is a run that did not do what it claims, reported as fine.
    rc=$EXIT_OK

    if [ "$SIGNAL" -ne 0 ]; then
        # An interrupted run is not a completed one, even if everything else
        # went well. 128+N is the shell convention.
        rc=$((128 + SIGNAL))
    elif [ "$SETUP_RC" -ne 0 ]; then
        # The interface could not be taken down, or the pre-state could not be
        # saved. The experiment did not start.
        rc=$EXIT_LOAD_NOT_RUN
    elif [ "$LOAD_RAN" -eq 0 ]; then
        # E3: this is the case round 11 called success. The setup completed but
        # the load never executed, so there is no experiment to report on.
        rc=$EXIT_LOAD_NOT_RUN
    elif [ "$LOAD_RC" -ne 0 ]; then
        rc=$LOAD_RC
    fi
    # ROUND 13 (E7): the restore failure now OVERRIDES the signal code, because
    # "the host is not back in its normal state" is the fact the caller must act
    # on. The signal is still reported below.
    if [ "$RESTORE_RC" -ne 0 ]; then
        rc=$EXIT_RESTORE_FAILED
    fi

    say ""
    say "SUMMARY"
    say "  setup status   : $([ "$SETUP_RC" -eq 0 ] && echo 0 || echo "$SETUP_RC (interface not taken down / state not saved)")"
    if [ "$LOAD_RAN" -eq 1 ]; then
        say "  load status    : $LOAD_RC"
    else
        say "  load status    : NOT RUN"
    fi
    if [ "$SIGNAL" -ne 0 ]; then
        say "  signal         : SIG$SIGNAL (interrupted)"
    else
        say "  signal         : none"
    fi
    if [ "$RESTORE_RC" -ne 0 ]; then
        say "  restore status : 1 (MANAGEMENT LINK NOT RESTORED)"
    else
        say "  restore status : 0"
    fi
    say "  exit code      : $rc"
    if [ "$SIGNAL" -ne 0 ] && [ "$RESTORE_RC" -ne 0 ]; then
        say "  NOTE           : this run was interrupted AND the link was not"
        say "                   restored. Exit $EXIT_RESTORE_FAILED reports the"
        say "                   link; SIG$SIGNAL is recorded above."
    fi

    if [ "$RESTORE_RC" -ne 0 ]; then
        say_err ""
        say_err "RESULT: FAILED -- the management interface did not come back to"
        say_err "        its SAVED state. Exit $EXIT_RESTORE_FAILED specifically means:"
        say_err "        the experiment may have succeeded, but the machine is not"
        say_err "        back in its normal state. Do not treat this run as clean."
        if [ "$SIGNAL" -ne 0 ]; then
            say_err "        The run was ALSO interrupted by SIG$SIGNAL."
        fi
    elif [ "$SIGNAL" -ne 0 ]; then
        say_err "RESULT: INTERRUPTED -- SIG$SIGNAL. The link was restored, but an"
        say_err "        interrupted run is not a completed experiment. Exit"
        say_err "        $rc is 128+$SIGNAL by the shell convention."
    elif [ "$LOAD_RAN" -eq 0 ]; then
        say_err "RESULT: FAILED -- the load never ran. Exit $EXIT_LOAD_NOT_RUN."
        say_err "        Round 11 reported this as success."
    elif [ "$LOAD_RC" -ne 0 ]; then
        say_err "RESULT: FAILED -- the load returned $LOAD_RC (link restored)."
    else
        say "RESULT: OK -- load succeeded and $MGMT_IFACE was restored to its saved state."
    fi
    exit "$rc"
}

# ---- self test ---------------------------------------------------------
#
# Drives every branch with stubs, so the exit-code and precondition logic is
# verified WITHOUT taking a real interface down. The stubs are real programs
# that receive the real arguments and keep real state, so the script's own
# argument passing and sequencing are exercised rather than bypassed.
selftest() {
    echo "en2-run.sh self test (no real interface is touched)"
    echo "==================================================="
    tmp=$(mktemp -d)
    mkdir -p "$tmp/state"

    cat > "$tmp/ifconfig" <<'STUB'
#!/bin/sh
S=${STUB_STATE:?}
case "$1" in
  -l) echo "en0 en1 en2"; exit 0 ;;
esac
iface=$1; shift
up=$(cat "$S/$iface.up" 2>/dev/null || echo 0)
case "$1" in
  up)   echo 1 > "$S/$iface.up"; exit 0 ;;
  down) echo 0 > "$S/$iface.up"; exit 0 ;;
esac
# ROUND 13 (E8): the ADMIN state is the UP flag, which is what `ifconfig up`
# and `ifconfig down` change. `status: active` is the LINK state and is
# deliberately NOT tied to the admin bit here, because on the real machine an
# interface can be admin-UP with no link. The stub mirrors that: the UP flag
# comes from the state file, the status line is always "active" once UP.
[ "$up" = "1" ] || exit 0
flags="UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST"
echo "$iface: flags=8863<$flags> mtu 1500"
echo "	ether $(cat "$S/$iface.mac" 2>/dev/null || echo 00:00:00:00:00:00)"
ip=$(cat "$S/$iface.ip" 2>/dev/null)
mask=$(cat "$S/$iface.mask" 2>/dev/null || echo 0xffffff00)
[ -n "$ip" ] && echo "	inet $ip netmask $mask broadcast 192.168.50.255"
echo "	status: active"
exit 0
STUB
    cat > "$tmp/netstat" <<'STUB'
#!/bin/sh
S=${STUB_STATE:?}
for i in en0 en1 en2; do
    up=$(cat "$S/$i.up" 2>/dev/null || echo 0)
    has=$(cat "$S/$i.route" 2>/dev/null || echo 0)
    gw=$(cat "$S/$i.gw" 2>/dev/null || echo 192.168.50.1)
    if [ "$up" = "1" ] && [ "$has" = "1" ]; then
        echo "default            $gw       UGScg          $i"
    fi
done
STUB
    # The sudo stub must FORWARD its arguments, not swallow them: a stub that
    # ran nothing would make every "ifconfig down" succeed vacuously and the
    # test would pass on a script that never calls ifconfig at all.
    cat > "$tmp/sudo" <<'STUB'
#!/bin/sh
exec "$@"
STUB
    printf '#!/bin/sh\nexit 0\n' > "$tmp/sleep"
    chmod +x "$tmp"/ifconfig "$tmp"/netstat "$tmp"/sudo "$tmp"/sleep

    reset_state() {
        printf '1\n' > "$tmp/state/en0.up"
        printf '192.168.50.204\n' > "$tmp/state/en0.ip"
        printf '0xffffff00\n' > "$tmp/state/en0.mask"
        printf '1\n' > "$tmp/state/en0.route"
        printf '192.168.50.1\n' > "$tmp/state/en0.gw"
        printf '00:e0:4c:68:ab:03\n' > "$tmp/state/en0.mac"
        printf '0\n' > "$tmp/state/en1.up"
        printf '\n' > "$tmp/state/en1.ip"
        printf '0xffffff00\n' > "$tmp/state/en1.mask"
        printf '0\n' > "$tmp/state/en1.route"
        printf '192.168.50.1\n' > "$tmp/state/en1.gw"
        printf '00:00:00:00:00:01\n' > "$tmp/state/en1.mac"
        printf '1\n' > "$tmp/state/en2.up"
        printf '192.168.50.216\n' > "$tmp/state/en2.ip"
        printf '0xffffff00\n' > "$tmp/state/en2.mask"
        printf '0\n' > "$tmp/state/en2.route"
        printf '192.168.50.1\n' > "$tmp/state/en2.gw"
        printf '1c:86:0b:3b:0b:bd\n' > "$tmp/state/en2.mac"
    }
    reset_state

    fails=0
    # run_case <name> <expected-exit> <session-addr-or-empty> <cmd...>
    run_case() {
        name=$1; want=$2; sess=$3; shift 3
        out=$(STUB_STATE="$tmp/state" \
              IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
              SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
              IFCONFIG_LIST="en0 en1 en2" \
              SSH_CONNECTION="${sess:+10.0.0.1 5000 $sess 22}" \
              sh "$0" "$@" 2>&1)
        got=$?
        if [ "$got" = "$want" ]; then
            printf '  %-52s exit=%-3s OK\n' "$name" "$got"
        else
            printf '  %-52s exit=%-3s WANT %s  <-- FAIL\n' "$name" "$got" "$want"
            printf '%s\n' "$out" | sed 's/^/      /'
            fails=$((fails + 1))
        fi
        reset_state
    }

    echo
    echo "  --- the safety gate ---"
    run_case "session on mgmt (en0) is refused"          1 192.168.50.204 --run true
    run_case "session on a third iface (en1) is refused" 1 192.168.50.1   --run true
    run_case "session from an unknown address refused"   1 10.9.9.9       --run true
    run_case "no SSH_CONNECTION is refused"              1 ''             --run true

    echo
    echo "  --- the normal path ---"
    run_case "session on target, load OK -> 0"           0 192.168.50.216 --run true
    run_case "session on target, load fails -> 7"        7 192.168.50.216 --run sh -c 'exit 7'

    echo
    echo "  --- E3: the load did not run ---"
    #
    # The management interface cannot be brought down, so the load must not
    # run. Round 11 exited 0 here: CMD_RAN stayed 0 and CMD_RC stayed 0, so
    # rc=0. An experiment that never happened is not a success.
    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/nonexistent-sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run true 2>&1)
    got=$?
    if [ "$got" = "1" ]; then
        printf '  %-52s exit=%-3s OK\n' "interface down fails, load not run -> 1" "$got"
    else
        printf '  %-52s exit=%-3s WANT 1  <-- FAIL\n' "interface down fails, load not run -> 1" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    echo
    echo "  --- E4: a signal must not be reported as success ---"
    #
    # The load sends SIGTERM to its own shell's parent chain by killing the
    # script. We simulate it by having the load raise SIGTERM on the script's
    # PID, which is what an operator's Ctrl-C or a wrapper's timeout does.
    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run sh -c 'kill -TERM $PPID; sleep 0.2' 2>&1)
    got=$?
    if [ "$got" = "143" ]; then
        printf '  %-52s exit=%-3s OK\n' "SIGTERM during load -> 143" "$got"
    else
        printf '  %-52s exit=%-3s WANT 143  <-- FAIL\n' "SIGTERM during load -> 143" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    echo
    echo "  --- E5/E6: the pre-state is saved and required ---"
    #
    # A management interface with no address cannot be restored, so the script
    # must refuse BEFORE touching it.
    printf '1\n' > "$tmp/state/en0.up"
    printf '\n' > "$tmp/state/en0.ip"
    printf '1\n' > "$tmp/state/en0.route"
    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run true 2>&1)
    got=$?
    en0_up=$(cat "$tmp/state/en0.up")
    if [ "$got" != "0" ] && [ "$en0_up" = "1" ]; then
        printf '  %-52s exit=%-3s OK (iface untouched)\n' "mgmt without an address is refused" "$got"
    else
        printf '  %-52s exit=%-3s WANT non-zero and en0 still up  <-- FAIL\n' "mgmt without an address is refused" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    # A management interface with no default route cannot restore the
    # operator's path, so it is refused for the same reason.
    printf '0\n' > "$tmp/state/en0.route"
    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run true 2>&1)
    got=$?
    en0_up=$(cat "$tmp/state/en0.up")
    if [ "$got" != "0" ] && [ "$en0_up" = "1" ]; then
        printf '  %-52s exit=%-3s OK (iface untouched)\n' "mgmt without a default route is refused" "$got"
    else
        printf '  %-52s exit=%-3s WANT non-zero and en0 still up  <-- FAIL\n' "mgmt without a default route is refused" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    echo
    echo "  --- the restore-failure case (the round-10 defect) ---"
    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run sh -c 'printf 0 > "$STUB_STATE/en0.route"' 2>&1)
    got=$?
    if [ "$got" = "90" ]; then
        printf '  %-52s exit=%-3s OK\n' "restore fails -> 90, not 0" "$got"
    else
        printf '  %-52s exit=%-3s WANT 90  <-- FAIL\n' "restore fails -> 90, not 0" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    # A restore that brings the interface back on a DIFFERENT address is not a
    # restore. Round 11 accepted any address.
    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run sh -c 'printf "192.168.50.99\n" > "$STUB_STATE/en0.ip"' 2>&1)
    got=$?
    if [ "$got" = "90" ]; then
        printf '  %-52s exit=%-3s OK\n' "restore to a DIFFERENT address -> 90" "$got"
    else
        printf '  %-52s exit=%-3s WANT 90  <-- FAIL\n' "restore to a DIFFERENT address -> 90" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    # ------------------------------------------------------------------
    echo
    echo "  --- E8: the ADMIN state, not the link state ---"
    # ------------------------------------------------------------------
    #
    # An interface that is administratively DOWN while still carrying an
    # address and a default route is a state someone configured deliberately.
    # Round 12 read `status: active` (a LINK state) and never looked at the UP
    # flag, so it took such an interface down and then "restored" it by bringing
    # it UP -- changing the state it was supposed to preserve.
    #
    # The stub's UP flag is what `ifconfig up`/`down` set, and `status: active`
    # follows it, so this is the same relationship the real machine has when a
    # link is present. The point of the case is that the UP flag is now READ.
    printf '0\n' > "$tmp/state/en0.up"
    printf '192.168.50.204\n' > "$tmp/state/en0.ip"
    printf '0xffffff00\n' > "$tmp/state/en0.mask"
    printf '1\n' > "$tmp/state/en0.route"
    printf '192.168.50.1\n' > "$tmp/state/en0.gw"
    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run true 2>&1)
    got=$?
    en0_up=$(cat "$tmp/state/en0.up")
    if [ "$got" != "0" ] && [ "$en0_up" = "0" ]; then
        printf '  %-52s exit=%-3s OK (left as it was)\n' "admin-down mgmt with config is refused" "$got"
    else
        printf '  %-52s exit=%-3s WANT non-zero and en0 still DOWN  <-- FAIL\n' "admin-down mgmt with config is refused" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    # ------------------------------------------------------------------
    echo
    echo "  --- E9: netmask and gateway are part of the saved state ---"
    # ------------------------------------------------------------------
    #
    # Round 12 compared only the address. A restore that came back with a
    # different mask, or with a different default gateway, passed as clean.
    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run sh -c 'printf "0xffff0000\n" > "$STUB_STATE/en0.mask"' 2>&1)
    got=$?
    if [ "$got" = "90" ]; then
        printf '  %-52s exit=%-3s OK\n' "restore with a DIFFERENT netmask -> 90" "$got"
    else
        printf '  %-52s exit=%-3s WANT 90  <-- FAIL\n' "restore with a DIFFERENT netmask -> 90" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run sh -c 'printf "192.168.50.254\n" > "$STUB_STATE/en0.gw"' 2>&1)
    got=$?
    if [ "$got" = "90" ]; then
        printf '  %-52s exit=%-3s OK\n' "restore with a DIFFERENT gateway -> 90" "$got"
    else
        printf '  %-52s exit=%-3s WANT 90  <-- FAIL\n' "restore with a DIFFERENT gateway -> 90" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    # The default route moving to a DIFFERENT interface is also a different
    # state: the operator's path would leave by en2, not en0.
    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run sh -c 'printf 0 > "$STUB_STATE/en0.route"; printf 1 > "$STUB_STATE/en2.route"' 2>&1)
    got=$?
    if [ "$got" = "90" ]; then
        printf '  %-52s exit=%-3s OK\n' "default route moved to another iface -> 90" "$got"
    else
        printf '  %-52s exit=%-3s WANT 90  <-- FAIL\n' "default route moved to another iface -> 90" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    # ------------------------------------------------------------------
    echo
    echo "  --- E7: a signal survives a FAILED restore ---"
    # ------------------------------------------------------------------
    #
    # Round 12 computed 128+N and then replaced the code with 90 only when the
    # code was still 0, so an interrupted run whose restore ALSO failed exited
    # 128+N and the RESULT text talked only about the restore. Both facts must
    # now be recorded, and the restore failure must win the exit code because
    # that is the fact the caller has to act on.
    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run sh -c 'printf 0 > "$STUB_STATE/en0.route"; kill -TERM $PPID; sleep 0.2' 2>&1)
    got=$?
    has_sig=$(printf '%s' "$out" | grep -c 'SIG15')
    if [ "$got" = "90" ] && [ "$has_sig" -ge 1 ]; then
        printf '  %-52s exit=%-3s OK (SIG15 recorded)\n' "SIGTERM + failed restore -> 90, signal kept" "$got"
    else
        printf '  %-52s exit=%-3s WANT 90 with SIG15 in the summary  <-- FAIL\n' "SIGTERM + failed restore -> 90, signal kept" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    # SIGINT is 2, so an interrupted run with a healthy link exits 130.
    out=$(STUB_STATE="$tmp/state" \
          IFCONFIG="$tmp/ifconfig" NETSTAT="$tmp/netstat" \
          SUDO="$tmp/sudo" SLEEP="$tmp/sleep" \
          IFCONFIG_LIST="en0 en1 en2" \
          SSH_CONNECTION="10.0.0.1 5000 192.168.50.216 22" \
          sh "$0" --run sh -c 'kill -INT $PPID; sleep 0.2' 2>&1)
    got=$?
    if [ "$got" = "130" ]; then
        printf '  %-52s exit=%-3s OK\n' "SIGINT during load -> 130" "$got"
    else
        printf '  %-52s exit=%-3s WANT 130  <-- FAIL\n' "SIGINT during load -> 130" "$got"
        printf '%s\n' "$out" | sed 's/^/      /'
        fails=$((fails + 1))
    fi
    reset_state

    echo
    if [ "$fails" -eq 0 ]; then
        echo "  RESULT: ALL SELF-TEST CASES BEHAVE CORRECTLY"
    else
        echo "  RESULT: $fails CASE(S) FAILED"
    fi
    rm -rf "$tmp"
    return "$fails"
}

case "${1:-}" in
    --check)
        ip=$(target_ip)
        [ -n "$ip" ] || die "$TARGET_IFACE has no IPv4 address"
        say "target $TARGET_IFACE = $ip"
        say "management interface to disable = $MGMT_IFACE"
        say "its address now = $(iface_inet "$MGMT_IFACE")"
        say ""
        say "NOTE: this only confirms $TARGET_IFACE has an address. The real"
        say "      step-1 check must be run FROM THE OPERATOR MACHINE:"
        say "        ssh <user>@$ip 'uname -r'"
        say "      If that fails, do not run --run."
        ;;

    --restore)
        restore_mgmt
        exit $?
        ;;

    --selftest)
        selftest
        exit $?
        ;;

    --run)
        shift
        [ $# -gt 0 ] || die "usage: en2-run.sh --run <cmd...>"

        mgmt=$MGMT_IFACE
        [ -n "$mgmt" ] || die "cannot determine the management interface"
        [ "$mgmt" != "$TARGET_IFACE" ] || die "management and target are the same interface ($mgmt)"

        # THE SAFETY GATE (round-11 fix E2).
        sess_addr=$(session_local_addr)
        arrived_on=$(iface_of_addr "$sess_addr" || true)
        tgt_addr=$(target_ip)
        say "session local address: ${sess_addr:-<none>}"
        say "session arrived on   : ${arrived_on:-unknown}"
        say "management interface : $mgmt   target interface: $TARGET_IFACE ($tgt_addr)"

        if [ -z "${SSH_CONNECTION:-}" ]; then
            die "SSH_CONNECTION is not set: this does not look like an SSH
     session. Refusing to disable $mgmt, because the surviving path
     cannot be established."
        fi
        if [ -z "$sess_addr" ]; then
            die "cannot determine which interface this session arrived on;
     refusing to disable $mgmt blind"
        fi
        if [ -z "$tgt_addr" ]; then
            die "$TARGET_IFACE has no IPv4 address, so it cannot be the path
     that survives; refusing to disable $mgmt"
        fi
        if [ "$sess_addr" != "$tgt_addr" ]; then
            die "this session arrived on ${arrived_on:-an unknown interface}
     ($sess_addr), not on $TARGET_IFACE ($tgt_addr). Bringing $mgmt down
     would cut the only path back. Connect over the target interface:
        ssh <user>@$tgt_addr 'sh $0 --run <cmd...>'"
        fi

        # E6: the pre-state must be saveable BEFORE anything changes. If it is
        # not, the script cannot restore it and must not proceed.
        if ! save_mgmt_state; then
            SETUP_RC=1
            say_err "step 2: refusing to continue; $mgmt was not touched."
            finish
        fi

        # ROUND 13 (E7): the trap argument is the SIGNAL NUMBER, and SIGINT is
        # 2, not 1. Round 12 wrote `on_signal 1` for INT, so a Ctrl-C was
        # recorded as SIG1 (SIGHUP) and the script exited 129 where the shell
        # convention -- and this script's own documentation -- says 130.
        # The self-test caught it: "SIGINT during load -> 130" got 129.
        trap 'on_exit' EXIT
        trap 'on_signal 2'  INT
        trap 'on_signal 15' TERM

        say "step 3: bringing $mgmt down"
        if ! $SUDO "$IFCONFIG" "$mgmt" down; then
            SETUP_RC=1
            say_err "step 3 FAILED: could not bring $mgmt down"
            say_err "  The load will NOT run: the experiment needs $mgmt out of"
            say_err "  the way, and running it with the interface still up would"
            say_err "  make the load's egress interface ambiguous."
            on_exit
            finish
        fi

        say "step 4: running: $*"
        LOAD_RAN=1
        "$@"
        LOAD_RC=$?
        say "step 4: finished with rc=$LOAD_RC"

        on_exit
        finish
        ;;

    *)
        cat >&2 <<EOF
usage:
  en2-run.sh --check              confirm $TARGET_IFACE has an address (changes nothing)
  en2-run.sh --run <cmd...>       steps 2..6 around <cmd>
  en2-run.sh --restore            bring the management iface back up
  en2-run.sh --selftest           exercise every branch with command stubs

INTENDED USE: run this ON THE MAC, invoked over an SSH connection that
arrived via the TARGET interface:

  # from the operator machine:
  ssh <mac-en2-ip> 'sh ~/r12work/tools/dev/en2-run.sh --run <cmd...>'

That way bringing the management interface down cannot cut your session.
--run refuses unless the session arrived on the TARGET interface's own
address; anything else is treated as unsafe.

environment:
  TARGET_IFACE   default en2
  MGMT_IFACE     default en0 (named explicitly: en0 and en2 share a subnet
                 here, so the default route does not identify the mgmt link)
  IFCONFIG/NETSTAT/SUDO/SLEEP   command hooks, for --selftest

exit codes:
  0   the load succeeded AND the management interface was restored to its
      saved address and route
  1   the load did not run (setup failed, or the interface could not be
      taken down). Round 11 reported this as success.
  N   the load's own exit status (link restored)
  90  the management interface did NOT come back to its saved state. The
      experiment may have succeeded, but the machine is not in its normal
      state.
  128+N  interrupted by signal N. An interrupted run is not a completed
      experiment, even if the link was restored.

This script NEVER writes an address, netmask or route. If you find yourself
wanting to change a subnet to make traffic use $TARGET_IFACE, stop: use this
instead.
EOF
        exit 2
        ;;
esac
