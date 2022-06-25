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

    macdb = MacLookup()
    macdb_updated = False

    result = {}

    @staticmethod
    def get_gateways() -> dict:
        """ Get all network interfaces available on the system.

        :return dict: network interfaces available on the system
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

    @staticmethod
    def scan_ports(host: str, start: int = 0, end: int = 65535) -> dict:
        """ Scan host for opened ports.

        :param str host: host to scan for opened ports
        :param int start: first port
        :param int end: final port
        :return dict: dictionary of port and service name
        """

        ports = {}

        for port in range(start, end+1):
            sock = socket.socket()

            sock.settimeout(0.5)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            connected = sock.connect_ex((host, port)) == 0
            sock.close()

            if connected:
                try:
                    name = socket.getservbyport(port)
                except Exception:
                    name = 'tcpwrapped'

                ports.update({port: name})

        return ports

    def get_vendor(self, mac: str) -> str:
        """ Get vendor by MAC address.

        :param str mac: MAC address
        :return str: vendor name
        """

        if not self.macdb_updated:
            self.macdb.update_vendors()
            self.macdb_updated = True

        return self.macdb.lookup(mac)

    def get_platform(self, host: str) -> str:
        """ Detect platform by host.

        :param str host: host to detect platform by
        :return str: platform name
        """

        pack = IP(dst=host) / ICMP()
        response = sr1(pack, timeout=10, verbose=False)

        if response:
            if IP in response:
                ttl = response.getlayer(IP).ttl

                if ttl in self.os_ttl:
                    return self.os_ttl[ttl]

        return 'unix'

    def start_audit(self, gateway: str, iface: str) -> None:
        """ Start network audit.

        :param str gateway: gateway to start audit for
        :param str iface: interface to start audit on
        :return None: None
        """

        arp = ARP(pdst=gateway)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")

        response = srp(ether / arp, timeout=10, verbose=False)[0]

        if response:
            hosts = {}

            for _, recv in response:
                hosts.update({
                    recv.psrc: {
                        'mac': recv.psrc.hwsrc,
                        'vendor': self.get_vendor(recv.psrc.hwsrc),
                        'platform': self.get_platform(recv.psrc),
                        'ports': self.scan_ports(recv.psrc),
                        'vulns': {}
                    }
                })

            self.result.update({
                gateway: {
                    iface: hosts
                }
            })

    def audit_result(self) -> dict:
        """ Get network audit result.

        :return dict: network audit result
        """

        return self.result
