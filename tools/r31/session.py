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


def find_probe_entry(io, target=SERVICE):
    """Return the retained registry entry for the probe object.

    The probe is an unregistered IOService nub: it publishes properties but is
    not a published service, so IOServiceMatching/IOServiceGetMatchingService
    and IORegistryEntryIDMatching all return no match. It is a child of
    IOResources, so those children are walked first. The recursive walk from
    the root covers the whole IOService plane and can end early while other
    entries are published or terminated in parallel, which reported the probe
    as missing while it was in fact still attached and active.
    """
    ptr = ctypes.c_void_p
    io.IORegistryGetRootEntry.argtypes = [ctypes.c_uint32]
    io.IORegistryGetRootEntry.restype = ctypes.c_uint32
    io.IORegistryEntryFromPath.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    io.IORegistryEntryFromPath.restype = ctypes.c_uint32
    io.IORegistryEntryCreateIterator.argtypes = [ctypes.c_uint32, ctypes.c_char_p,
                                                 ctypes.c_uint32, ctypes.POINTER(ptr)]
    io.IORegistryEntryCreateIterator.restype = ctypes.c_int
    io.IOIteratorNext.argtypes = [ptr]
    io.IOIteratorNext.restype = ctypes.c_uint32
    io.IORegistryEntryGetName.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    io.IORegistryEntryGetName.restype = ctypes.c_int
    io.IOObjectConformsTo.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    io.IOObjectConformsTo.restype = ctypes.c_bool
    io.IOObjectRelease.argtypes = [ctypes.c_uint32]

    def search(start):
        iterator = ptr()
        if io.IORegistryEntryCreateIterator(start, b'IOService', 1,
                                            ctypes.byref(iterator)):
            return 0
        buffer = ctypes.create_string_buffer(256)
        try:
            while True:
                entry = io.IOIteratorNext(iterator)
                if not entry:
                    break
                if ((io.IORegistryEntryGetName(entry, buffer) == 0 and
                        buffer.value.decode('utf-8', 'replace') == target) or
                        io.IOObjectConformsTo(entry, target.encode('ascii'))):
                    return entry
                io.IOObjectRelease(entry)
        finally:
            if iterator.value:
                io.IOObjectRelease(iterator.value)
        return 0

    resources = io.IORegistryEntryFromPath(0, b'IOService:/IOResources')
    if resources:
        try:
            entry = search(resources)
        finally:
            io.IOObjectRelease(resources)
        if entry:
            return entry
    root = io.IORegistryGetRootEntry(0)
    if not root:
        raise RuntimeError('cannot get IORegistry root')
    try:
        entry = search(root)
    finally:
        io.IOObjectRelease(root)
    if not entry:
        raise RuntimeError('registry service not found: ' + target)
    return entry


def set_boolean_property(name, service_class=None, value=True):
    """Send one boolean-valued probe property RPC.

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

    service = 0
    if service_class:
        io.IOServiceMatching.argtypes = [ctypes.c_char_p]
        io.IOServiceMatching.restype = ptr
        io.IOServiceGetMatchingService.argtypes = [ctypes.c_uint32, ptr]
        io.IOServiceGetMatchingService.restype = ctypes.c_uint32
        matching = io.IOServiceMatching(service_class.encode('ascii'))
        if matching:
            service = io.IOServiceGetMatchingService(0, matching)
    if not service:
        service = find_probe_entry(io, service_class or SERVICE)
    key = properties = None
    try:
        key = cf.CFStringCreateWithCString(None, name.encode('ascii'), 0x08000100)
        if not key:
            raise RuntimeError('cannot create probe property key')
        boolean_value = ptr.in_dll(cf, 'kCFBooleanTrue' if value else 'kCFBooleanFalse')
        # The key and global boolean remain alive for this synchronous RPC.
        properties = cf.CFDictionaryCreate(None, (ptr * 1)(key),
                                           (ptr * 1)(boolean_value.value), 1, None, None)
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
