#!/usr/bin/env python3
"""Inspect or explicitly stop the service-owned device domain on macOS.

The accepted R31Stop registry-entry RPC remains the control interface. Status
also exposes Round33 domain ownership and setup/teardown worker boundaries.
"""
import argparse
import ctypes
import json
import re
import subprocess
import sys


SERVICE = 'org_example_AMDMapperProbe'
PREFIX = 'm2-3l-'
FIELDS = ('session-mode', 'session-state', 'session-start',
          'stop-request-time', 'session-end', 'tx-deadline')
DOMAIN_PREFIX = 'm2-3n-'
DOMAIN_FIELDS = ('domain-mode', 'domain-state', 'setup-worker-active',
                 'setup-worker-exit-time', 'root-pa', 'dt-pa', 'command-pa',
                 'install-count', 'teardown-start', 'teardown-end')


def parse_status(text):
    result = {}
    for prefix, fields in ((PREFIX, FIELDS), (DOMAIN_PREFIX, DOMAIN_FIELDS)):
        for name in fields:
            match = re.search(r'"' + prefix + name + r'"\s*=\s*(?:"([^"]*)"|(0x[0-9a-fA-F]+|\d+))', text)
            if match:
                value = match.group(1) if match.group(1) is not None else match.group(2)
                result[name] = int(value, 0) if re.fullmatch(r'0x[0-9a-fA-F]+|\d+', value) else value
    return result


def status():
    text = subprocess.run(['ioreg', '-l', '-w0', '-r', '-c', SERVICE],
                          capture_output=True, text=True, check=True).stdout
    return parse_status(text)


def find_probe_entry(io):
    """Return the retained registry entry for the probe object.

    The probe is an unregistered IOService nub: it publishes properties but is
    not a published service, so IOServiceMatching/IOServiceGetMatchingService
    and IORegistryEntryIDMatching all return no match. Walk the IOService plane
    and match the entry name, which is what ioreg -c reports as well.
    """
    ptr = ctypes.c_void_p
    io.IORegistryGetRootEntry.argtypes = [ctypes.c_uint32]
    io.IORegistryGetRootEntry.restype = ctypes.c_uint32
    io.IORegistryEntryCreateIterator.argtypes = [ctypes.c_uint32, ctypes.c_char_p,
                                                 ctypes.c_uint32, ctypes.POINTER(ptr)]
    io.IORegistryEntryCreateIterator.restype = ctypes.c_int
    io.IOIteratorNext.argtypes = [ptr]
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IORegistryEntryGetName.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    io.IORegistryEntryGetName.restype = ctypes.c_int
    io.IOObjectRelease.argtypes = [ctypes.c_uint32]
    root = io.IORegistryGetRootEntry(0)
    if not root:
        raise RuntimeError('cannot get IORegistry root')
    iterator = ptr()
    try:
        if io.IORegistryEntryCreateIterator(root, b'IOService', 1,
                                            ctypes.byref(iterator)):
            raise RuntimeError('cannot iterate IOService plane')
        buffer = ctypes.create_string_buffer(256)
        while True:
            entry = io.IOIteratorNext(iterator)
            if not entry:
                break
            if (io.IORegistryEntryGetName(entry, buffer) == 0 and
                    buffer.value.decode('utf-8', 'replace') == SERVICE):
                return entry
            io.IOObjectRelease(entry)
        raise RuntimeError('Round31 probe service not found')
    finally:
        if iterator:
            io.IOObjectRelease(iterator.value)
        io.IOObjectRelease(root)


def set_boolean_property(name):
    """Send one true-valued probe property RPC.

    Frameworks load only here, so importing the module and host-side protocol
    checks do not require macOS or any compiled Python extension.
    """
    if sys.platform != 'darwin':
        raise RuntimeError('probe property RPC requires macOS')
    io = ctypes.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
    cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    ptr = ctypes.c_void_p
    io.IORegistryEntrySetCFProperties.argtypes = [ctypes.c_uint32, ptr]
    io.IORegistryEntrySetCFProperties.restype = ctypes.c_uint32
    io.IOObjectRelease.argtypes = [ctypes.c_uint32]
    io.IOObjectRelease.restype = ctypes.c_uint32
    cf.CFStringCreateWithCString.argtypes = [ptr, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFStringCreateWithCString.restype = ptr
    cf.CFDictionaryCreate.argtypes = [ptr, ctypes.POINTER(ptr), ctypes.POINTER(ptr),
                                    ctypes.c_long, ptr, ptr]
    cf.CFDictionaryCreate.restype = ptr
    cf.CFRelease.argtypes = [ptr]
    cf.CFRelease.restype = None

    service = find_probe_entry(io)
    key = properties = None
    try:
        key = cf.CFStringCreateWithCString(None, name.encode('ascii'), 0x08000100)
        if not key:
            raise RuntimeError('cannot create probe property key')
        true_value = ptr.in_dll(cf, 'kCFBooleanTrue')
        # The key and global boolean remain alive for this synchronous RPC.
        properties = cf.CFDictionaryCreate(None, (ptr * 1)(key),
                                           (ptr * 1)(true_value.value), 1, None, None)
        if not properties:
            raise RuntimeError('cannot create probe property dictionary')
        result = io.IORegistryEntrySetCFProperties(service, properties)
        if result:
            raise RuntimeError('%s failed: IOReturn=0x%08x' % (name, result))
    finally:
        if properties:
            cf.CFRelease(properties)
        if key:
            cf.CFRelease(key)
        io.IOObjectRelease(service)


def stop():
    """Request the legacy service-owned experiment's asynchronous stop."""
    set_boolean_property('R31Stop')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'stop'))
    args = parser.parse_args()
    if args.action == 'stop':
        stop()
        print('R31Stop accepted; inspect status for final stopped state.')
    print(json.dumps(status(), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
