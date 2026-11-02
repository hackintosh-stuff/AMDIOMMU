#!/usr/bin/env python3
"""Inspect or explicitly stop the active Round31 mapper session on macOS."""
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


def parse_status(text):
    result = {}
    for name in FIELDS:
        match = re.search(r'"' + PREFIX + name + r'"\s*=\s*(?:"([^"]*)"|(0x[0-9a-fA-F]+|\d+))', text)
        if match:
            value = match.group(1) if match.group(1) is not None else match.group(2)
            result[name] = int(value, 0) if re.fullmatch(r'0x[0-9a-fA-F]+|\d+', value) else value
    return result


def status():
    text = subprocess.run(['ioreg', '-l', '-w0', '-r', '-c', SERVICE],
                          capture_output=True, text=True, check=True).stdout
    return parse_status(text)


def stop():
    """Send one R31Stop=true property RPC; kernel work completes asynchronously.

    Frameworks load only here, so importing the module and host-side protocol
    checks do not require macOS or any compiled Python extension.
    """
    if sys.platform != 'darwin':
        raise RuntimeError('Round31 stop requires macOS')
    io = ctypes.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
    cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    ptr = ctypes.c_void_p
    io.IOServiceMatching.argtypes = [ctypes.c_char_p]
    io.IOServiceMatching.restype = ptr
    io.IOServiceGetMatchingService.argtypes = [ctypes.c_uint32, ptr]
    io.IOServiceGetMatchingService.restype = ctypes.c_uint32
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

    matching = io.IOServiceMatching(SERVICE.encode('ascii'))
    if not matching:
        raise RuntimeError('cannot create probe service match')
    # IOServiceGetMatchingService consumes the matching dictionary.
    service = io.IOServiceGetMatchingService(0, matching)
    if not service:
        raise RuntimeError('Round31 probe service not found')
    key = properties = None
    try:
        key = cf.CFStringCreateWithCString(None, b'R31Stop', 0x08000100)
        if not key:
            raise RuntimeError('cannot create R31Stop property key')
        true_value = ptr.in_dll(cf, 'kCFBooleanTrue')
        # The key and global boolean remain alive for this synchronous RPC.
        properties = cf.CFDictionaryCreate(None, (ptr * 1)(key),
                                           (ptr * 1)(true_value.value), 1, None, None)
        if not properties:
            raise RuntimeError('cannot create R31Stop property dictionary')
        result = io.IORegistryEntrySetCFProperties(service, properties)
        if result:
            raise RuntimeError('R31Stop failed: IOReturn=0x%08x' % result)
    finally:
        if properties:
            cf.CFRelease(properties)
        if key:
            cf.CFRelease(key)
        io.IOObjectRelease(service)


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
