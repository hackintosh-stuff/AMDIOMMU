"""Use the shared selected/passthrough handshake before Lucy opens PCI."""
from pathlib import Path
import runpy

R45 = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'tcp4' /
                        'driver-template.py'))
WAIT_OLD = R45['WAIT_NEW']
WAIT_NEW = '''    pciDevice->retain();

    /* The same pre-open policy is used by the RTL8111 consumer. */
    if (!amd_iommu_policy::waitForMapper(pciDevice)) {
        IOLog("Selected AMDIOMMU mapper failed to become ready.\\n");
        result = false;
        goto error_open;
    }

    if (!pciDevice->open(this)) {'''
INCLUDE = '#include "amd_iommu_device_policy.hpp"\n'


def rewrite(text):
    return text.replace(WAIT_OLD, WAIT_NEW)


def patch(cpp):
    if cpp.count(WAIT_OLD) != 1:
        raise SystemExit('refused: round53 per-device policy wait anchor')
    return INCLUDE + rewrite(cpp)


def is_current(cpp):
    return cpp.count(INCLUDE) == 1 and cpp.count(WAIT_NEW) == 1
