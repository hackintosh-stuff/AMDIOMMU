#!/usr/bin/env python3
"""Reuse the accepted explicit-interface IPv6 bind/read-back path."""
from common import module
_base = module('_r53_network_base', 'tools/r52/network.py')
network, bind_interface = _base.network, _base.bind_interface
