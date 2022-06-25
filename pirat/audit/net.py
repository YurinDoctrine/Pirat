"""
MIT License

Copyright (c) 2020-2022 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import socket
import netaddr
import netifaces

from scapy.all import *
from max_vendor_lookup import MacLookup


class Net:
    """ Subclass of pirat.audit module.

    This subclass of pirat.audit module is intended for providing an
    implementation of network auditor.
    """

    os_ttl = {
        0x3c: 'macos',
        0x40: 'linux',
        0xff: 'solaris',
        0x80: 'windows'
    }

    def get_gateways():
        """ Get all network interfaces available on the system.

        :return dict: network interfaces available on the system.
        """

        gateways = {}

        ifaces = netifaces.interfaces()
        for iface in ifaces:
            addrs = netifaces.ifaddress(iface)

            if socket.AF_INET in addrs:
                addrs = addrs[socket.AF_INET][0]

                gateways.update({
                    iface: str(netaddr.IPNetwork(
                        '%s/%s' % (addrs['addr'], addrs['netmask'])
                    ))
                })

        return gateways
