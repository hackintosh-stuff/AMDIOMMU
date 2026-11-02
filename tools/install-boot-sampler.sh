#!/bin/sh
# install-boot-sampler.sh -- run ON THE MAC, BEFORE rebooting.
#
# WHY THIS EXISTS
# ---------------
# The probe fires its measurement window on a one-shot timer that starts when
# the kext loads, i.e. early in boot. SSH does not come up until much later,
# so a sampler started by hand after login would begin AFTER the window had
# already closed. Round 5 got away with it because the window happened to
# land after the sampler started; that is luck, not a method.
#
# So the sampler is installed as a LaunchDaemon that starts at boot and
# samples for a fixed span. It writes to a fixed directory, and this script
# also records the boot identity so the capture can be tied to a specific
# boot.
#
# Usage:
#   sudo sh install-boot-sampler.sh [seconds]
#
# Remove with:
#   sudo sh install-boot-sampler.sh --remove

set -eu

SECS="${1:-180}"
LABEL="org.example.amdiommu.dmasampler"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
OUTDIR="/var/tmp/amdiommu-dma"
SRC="$HOME/iommu-work/tools/dma-window-sampler.sh"

if [ "$SECS" = "--remove" ]; then
    sudo launchctl bootout system "$PLIST" 2>/dev/null || true
    sudo rm -f "$PLIST"
    echo "removed $PLIST"
    exit 0
fi

if [ ! -f "$SRC" ]; then
    echo "sampler not found: $SRC" >&2
    exit 1
fi

sudo mkdir -p "$OUTDIR" /usr/local/bin
sudo cp "$SRC" /usr/local/bin/amdiommu-dma-sampler.sh
sudo chmod 755 /usr/local/bin/amdiommu-dma-sampler.sh

# The wrapper records the boot time and the kext version alongside the
# samples, so the capture is self-identifying.
sudo tee /usr/local/bin/amdiommu-dma-wrapper.sh >/dev/null <<'WRAP'
#!/bin/sh
OUTDIR=/var/tmp/amdiommu-dma
mkdir -p "$OUTDIR"
STAMP=$(date +%Y%m%d-%H%M%S)
{
    echo "boot_stamp=$STAMP"
    echo "uname=$(uname -a)"
    echo "boottime=$(sysctl -n kern.boottime 2>/dev/null)"
    echo "kext=$(kmutil showloaded --list-only 2>/dev/null | grep -i amdmapper || echo none)"
    echo "bootargs=$(nvram boot-args 2>/dev/null)"
    echo "wrapper_start_ms=$(perl -MTime::HiRes=time -e 'printf "%d\n", time()*1000')"
} > "$OUTDIR/$STAMP.meta"
IFACE=en2 SAMPLE_MS=100 sh /usr/local/bin/amdiommu-dma-sampler.sh \
    __SECS__ "$OUTDIR/$STAMP.tsv" >> "$OUTDIR/$STAMP.log" 2>&1
echo "wrapper_done_ms=$(perl -MTime::HiRes=time -e 'printf "%d\n", time()*1000')" \
    >> "$OUTDIR/$STAMP.meta"
WRAP

sudo sed -i '' "s/__SECS__/$SECS/" /usr/local/bin/amdiommu-dma-wrapper.sh
sudo chmod 755 /usr/local/bin/amdiommu-dma-wrapper.sh

sudo tee "$PLIST" >/dev/null <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>/usr/local/bin/amdiommu-dma-wrapper.sh</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>LaunchOnlyOnce</key><true/>
    <key>StandardErrorPath</key><string>/var/tmp/amdiommu-dma/launchd.err</string>
    <key>StandardOutPath</key><string>/var/tmp/amdiommu-dma/launchd.out</string>
</dict>
</plist>
PLISTEOF

sudo chown root:wheel "$PLIST"
sudo chmod 644 "$PLIST"
plutil -lint "$PLIST"

# Clear any previous capture so the next boot's files are unambiguous.
sudo rm -f "$OUTDIR"/*.tsv "$OUTDIR"/*.meta "$OUTDIR"/*.log

echo "installed  : $PLIST"
echo "sampler    : /usr/local/bin/amdiommu-dma-sampler.sh"
echo "wrapper    : /usr/local/bin/amdiommu-dma-wrapper.sh"
echo "output dir : $OUTDIR"
echo "duration   : ${SECS}s from boot"
