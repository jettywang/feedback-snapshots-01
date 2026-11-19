# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
DHCP (Dynamic Host Configuration Protocol) and BOOTP

Implements:
- rfc951 - BOOTSTRAP PROTOCOL (BOOTP)
- rfc1542 - Clarifications and Extensions for the Bootstrap Protocol
- rfc1533 - DHCP Options and BOOTP Vendor Extensions
"""

try:
    from collections.abc import Iterable
except ImportError:
    # For backwards compatibility.  This was removed in Python 3.8
    from collections import Iterable
import random
import struct

import socket
import re

from scapy.ansmachine import AnsweringMachine
from scapy.base_classes import Net
from scapy.compat import chb, bytes_encode
from scapy.fields import (
    ByteEnumField,
    ByteField,
    Field,
    FieldListField,
    FlagsField,
    IntField,
    IPField,
    MACField,
    ShortField,
    StrEnumField,
    StrField,
    StrFixedLenField,
    XIntField,
)
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether, HARDWARE_TYPES
from scapy.packet import bind_layers, bind_bottom_up, Packet
from scapy.utils import atol, itom, ltoa, sane, str2mac, mac2str
from scapy.volatile import (
    RandBin,
    RandByte,
    RandField,
    RandIP,
    RandInt,
    RandNum,
    RandNumExpo,
    VolatileValue,
)

from scapy.arch import get_if_hwaddr
from scapy.sendrecv import srp1, sendp
from scapy.error import warning
from scapy.config import conf

# Typing imports
from typing import (
    List,
    Optional,
    Tuple,
    Union,
)

dhcpmagic = b"c\x82Sc"


class _BOOTP_chaddr(StrFixedLenField):
    def i2m(self, pkt, x):
        if isinstance(x, VolatileValue):
            x = x._fix()
        return MACField.i2m(self, pkt, x)

    def i2repr(self, pkt, v):
        if isinstance(v, VolatileValue):
            return repr(v)
        if pkt.htype == 1:  # Ethernet
            if v[6:] == b"\x00" * 10:  # Default padding
                return "%s (+ 10 nul pad)" % str2mac(v[:6])
            else:
                return "%s (pad: %s)" % (str2mac(v[:6]), v[6:])
        return super(_BOOTP_chaddr, self).i2repr(pkt, v)


class BOOTP(Packet):
    name = "BOOTP"
    fields_desc = [
        ByteEnumField("op", 1, {1: "BOOTREQUEST", 2: "BOOTREPLY"}),
        ByteEnumField("htype", 1, HARDWARE_TYPES),
        ByteField("hlen", 6),
        ByteField("hops", 0),
        XIntField("xid", 0),
        ShortField("secs", 0),
        FlagsField("flags", 0, 16, "???????????????B"),
        IPField("ciaddr", "0.0.0.0"),
        IPField("yiaddr", "0.0.0.0"),
        IPField("siaddr", "0.0.0.0"),
        IPField("giaddr", "0.0.0.0"),
        _BOOTP_chaddr("chaddr", b"", length=16),
        StrFixedLenField("sname", b"", length=64),
        StrFixedLenField("file", b"", length=128),
        StrEnumField("options", b"", {dhcpmagic: "DHCP magic"})]

    def guess_payload_class(self, payload):
        if self.options[:len(dhcpmagic)] == dhcpmagic:
            return DHCP
        else:
            return Packet.guess_payload_class(self, payload)

    def extract_padding(self, s):
        if self.options[:len(dhcpmagic)] == dhcpmagic:
            # set BOOTP options to DHCP magic cookie and make rest a payload of DHCP options  # noqa: E501
            payload = self.options[len(dhcpmagic):]
            self.options = self.options[:len(dhcpmagic)]
            return payload, None
        else:
            return b"", None

    def hashret(self):
        return struct.pack("!I", self.xid)

    def answers(self, other):
        if not isinstance(other, BOOTP):
            return 0
        return self.xid == other.xid


class _DHCPByteFieldListField(FieldListField):
    def randval(self):
        class _RandByteFieldList(RandField):
            def _fix(self):
                return [RandByte()] * int(RandByte())
        return _RandByteFieldList()


class RandClasslessStaticRoutesField(RandField):
    """
    A RandValue for classless static routes
    """

    def _fix(self):
        return "%s/%d:%s" % (RandIP(), RandNum(0, 32), RandIP())


class ClasslessFieldListField(FieldListField):
    def randval(self):
        class _RandClasslessField(RandField):
            def _fix(self):
                return [RandClasslessStaticRoutesField()] * int(RandNum(1, 28))
        return _RandClasslessField()


class ClasslessStaticRoutesField(Field):
    """
    RFC 3442 defines classless static routes as up to 9 bytes per entry:

    # Code Len Destination 1    Router 1
    +-----+---+----+-----+----+----+----+----+----+
    | 121 | n | d1 | ... | dN | r1 | r2 | r3 | r4 |
    +-----+---+----+-----+----+----+----+----+----+

    Destination first byte contains one octet describing the width followed
    by all the significant octets of the subnet.
    """

    def m2i(self, pkt, x):
        # type: (Packet, bytes) -> str
        # b'\x20\x01\x02\x03\x04\t\x08\x07\x06' -> (1.2.3.4/32:9.8.7.6)
        prefix = x[0]

        octets = (prefix + 7) // 8
        # Create the destination IP by using the number of octets
        # and padding up to 4 bytes to ensure a valid IP.
        dest = x[1:1 + octets]
        dest = socket.inet_ntoa(dest.ljust(4, b'\x00'))

        router = x[1 + octets:5 + octets]
        router = socket.inet_ntoa(router)

        return dest + "/" + str(prefix) + ":" + router

    def i2m(self, pkt, x):
        # type: (Packet, str) -> bytes
        # (1.2.3.4/32:9.8.7.6) -> b'\x20\x01\x02\x03\x04\t\x08\x07\x06'
        if not x:
            return b''

        spx = re.split('/|:', str(x))
        prefix = int(spx[1])
        # if prefix is invalid value ( 0 > prefix > 32 ) then break
        if prefix > 32 or prefix < 0:
            warning("Invalid prefix value: %d (0x%x)", prefix, prefix)
            return b''
        octets = (prefix + 7) // 8
        dest = socket.inet_aton(spx[0])[:octets]
        router = socket.inet_aton(spx[2])
        return struct.pack('b', prefix) + dest + router

    def getfield(self, pkt, s):
        prefix = s[0]
        route_len = 5 + (prefix + 7) // 8
        return s[route_len:], self.m2i(pkt, s[:route_len])

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def randval(self):
        return RandClasslessStaticRoutesField()


# DHCP_UNKNOWN, DHCP_IP, DHCP_IPLIST, DHCP_TYPE \
# = range(4)
#

# DHCP Options and BOOTP Vendor Extensions


DHCPTypes = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
    9: "force_renew",
    10: "lease_query",
    11: "lease_unassigned",
    12: "lease_unknown",
    13: "lease_active",
}

DHCPOptions = {
    0: "pad",
    1: IPField("subnet_mask", "0.0.0.0"),
    2: IntField("time_zone", 500),
    3: IPField("router", "0.0.0.0"),
    4: IPField("time_server", "0.0.0.0"),
    5: IPField("IEN_name_server", "0.0.0.0"),
    6: IPField("name_server", "0.0.0.0"),
    7: IPField("log_server", "0.0.0.0"),
    8: IPField("cookie_server", "0.0.0.0"),
    9: IPField("lpr_server", "0.0.0.0"),
    10: IPField("impress-servers", "0.0.0.0"),
    11: IPField("resource-location-servers", "0.0.0.0"),
    12: "hostname",
    13: ShortField("boot-size", 1000),
    14: "dump_path",
    15: "domain",
    16: IPField("swap-server", "0.0.0.0"),
    17: "root_disk_path",
    18: "extensions-path",
    19: ByteField("ip-forwarding", 0),
    20: ByteField("non-local-source-routing", 0),
    21: IPField("policy-filter", "0.0.0.0"),
    22: ShortField("max_dgram_reass_size", 300),
    23: ByteField("default_ttl", 50),
    24: IntField("pmtu_timeout", 1000),
    25: ShortField("path-mtu-plateau-table", 1000),
    26: ShortField("interface-mtu", 50),
    27: ByteField("all-subnets-local", 0),
    28: IPField("broadcast_address", "0.0.0.0"),
    29: ByteField("perform-mask-discovery", 0),
    30: ByteField("mask-supplier", 0),
    31: ByteField("router-discovery", 0),
    32: IPField("router-solicitation-address", "0.0.0.0"),
    33: IPField("static-routes", "0.0.0.0"),
    34: ByteField("trailer-encapsulation", 0),
    35: IntField("arp_cache_timeout", 1000),
    36: ByteField("ieee802-3-encapsulation", 0),
    37: ByteField("tcp_ttl", 100),
    38: IntField("tcp_keepalive_interval", 1000),
    39: ByteField("tcp_keepalive_garbage", 0),
    40: StrField("NIS_domain", "www.example.com"),
    41: IPField("NIS_server", "0.0.0.0"),
    42: IPField("NTP_server", "0.0.0.0"),
    43: "vendor_specific",
    44: IPField("NetBIOS_server", "0.0.0.0"),
    45: IPField("NetBIOS_dist_server", "0.0.0.0"),
    46: ByteField("NetBIOS_node_type", 100),
    47: "netbios-scope",
    48: IPField("font-servers", "0.0.0.0"),
    49: IPField("x-display-manager", "0.0.0.0"),
    50: IPField("requested_addr", "0.0.0.0"),
    51: IntField("lease_time", 43200),
    52: ByteField("dhcp-option-overload", 100),
    53: ByteEnumField("message-type", 1, DHCPTypes),
    54: IPField("server_id", "0.0.0.0"),
    55: _DHCPByteFieldListField(
        "param_req_list", [],
        ByteField("opcode", 0)),
    56: "error_message",
    57: ShortField("max_dhcp_size", 1500),
    58: IntField("renewal_time", 21600),
    59: IntField("rebinding_time", 37800),
    60: StrField("vendor_class_id", "id"),
    61: StrField("client_id", ""),
    62: "nwip-domain-name",
    64: "NISplus_domain",
    65: IPField("NISplus_server", "0.0.0.0"),
    66: "tftp_server_name",
    67: StrField("boot-file-name", ""),
    68: IPField("mobile-ip-home-agent", "0.0.0.0"),
    69: IPField("SMTP_server", "0.0.0.0"),
    70: IPField("POP3_server", "0.0.0.0"),
    71: IPField("NNTP_server", "0.0.0.0"),
    72: IPField("WWW_server", "0.0.0.0"),
    73: IPField("Finger_server", "0.0.0.0"),
    74: IPField("IRC_server", "0.0.0.0"),
    75: IPField("StreetTalk_server", "0.0.0.0"),
    76: IPField("StreetTalk_Dir_Assistance", "0.0.0.0"),
    77: "user_class",
    78: "slp_service_agent",
    79: "slp_service_scope",
    80: "rapid_commit",
    81: "client_FQDN",
    82: "relay_agent_information",
    85: IPField("nds-server", "0.0.0.0"),
    86: StrField("nds-tree-name", ""),
    87: StrField("nds-context", ""),
    88: "bcms-controller-namesi",
    89: IPField("bcms-controller-address", "0.0.0.0"),
    91: IntField("client-last-transaction-time", 1000),
    92: IPField("associated-ip", "0.0.0.0"),
    93: "pxe_client_architecture",
    94: "pxe_client_network_interface",
    97: "pxe_client_machine_identifier",
    98: StrField("uap-servers", ""),
    100: StrField("pcode", ""),
    101: StrField("tcode", ""),
    108: IntField("ipv6-only-preferred", 0),
    112: IPField("netinfo-server-address", "0.0.0.0"),
    113: StrField("netinfo-server-tag", ""),
    114: StrField("captive-portal", ""),
    116: ByteField("auto-config", 0),
    117: ShortField("name-service-search", 0,),
    118: IPField("subnet-selection", "0.0.0.0"),
    121: ClasslessFieldListField(
        "classless_static_routes",
        [],
        ClasslessStaticRoutesField("route", 0)),
    124: "vendor_class",
    125: "vendor_specific_information",
    128: IPField("tftp_server_ip_address", "0.0.0.0"),
    136: IPField("pana-agent", "0.0.0.0"),
    137: "v4-lost",
    138: IPField("capwap-ac-v4", "0.0.0.0"),
    141: "sip_ua_service_domains",
    145: _DHCPByteFieldListField(
         "forcerenew_nonce_capable", [],
         ByteEnumField("algorithm", 1, {1: "HMAC-MD5"})),
    146: "rdnss-selection",
    150: IPField("tftp_server_address", "0.0.0.0"),
    159: "v4-portparams",
    160: StrField("v4-captive-portal", ""),
    161: StrField("mud-url", ""),
    208: "pxelinux_magic",
    209: "pxelinux_configuration_file",
    210: "pxelinux_path_prefix",
    211: "pxelinux_reboot_time",
    212: "option-6rd",
    213: "v4-access-domain",
    255: "end"
}

DHCPRevOptions = {}

for k, v in DHCPOptions.items():
    if isinstance(v, str):
        n = v
        v = None
    else:
        n = v.name
    DHCPRevOptions[n] = (k, v)
del n
del v
del k

# Option 52 "DHCP Option Overload" (RFC 2132 section 9.3)
DHCP_OVERLOAD_FILE = 1
DHCP_OVERLOAD_SNAME = 2
DHCP_OVERLOAD_BOTH = 3
DHCP_OVERLOAD_VALUES = (DHCP_OVERLOAD_FILE, DHCP_OVERLOAD_SNAME,
                        DHCP_OVERLOAD_BOTH)

# Sources of a DHCP option fragment. The numeric value also gives the order in
# which the overloaded areas are interpreted after the main options area
# (RFC 3396 section 4): the "file" field first, then the "sname" field.
DHCP_OPTION_AREA_OPTIONS = "options"
DHCP_OPTION_AREA_FILE = "file"
DHCP_OPTION_AREA_SNAME = "sname"


class DHCPOptionFragment(object):
    """
    A single option TLV as found in a DHCP message, kept together with the
    area it was read from and its position inside that area.

    Duplicate instances of an option are preserved as separate fragments so
    that long values split across several TLVs (RFC 3396) can be concatenated
    without hiding any piece of the original message.
    """
    __slots__ = ["option", "name", "value", "source", "position", "truncated"]

    def __init__(self, option, name, value, source, position, truncated=False):
        self.option = option
        self.name = name
        self.value = value
        self.source = source
        self.position = position
        self.truncated = truncated

    def __eq__(self, other):
        if not isinstance(other, DHCPOptionFragment):
            return NotImplemented
        return (
            self.option == other.option
            and self.name == other.name
            and self.value == other.value
            and self.source == other.source
            and self.position == other.position
            and self.truncated == other.truncated
        )

    def __ne__(self, other):
        ret = self.__eq__(other)
        if ret is NotImplemented:
            return ret
        return not ret

    def __repr__(self):
        if self.truncated:
            return "DHCPOptionFragment(%r, %r, source=%r, position=%d, truncated=True)" % (  # noqa: E501
                self.option, self.value, self.source, self.position)
        return "DHCPOptionFragment(%r, %r, %r, source=%r, position=%d)" % (
            self.option, self.name, self.value, self.source, self.position)


class DHCPOptionsAudit(object):
    """
    Result of :func:`dhcp_options_audit`.

    :param fragments: every option TLV in the order defined by the protocol
        (main options area, then "file", then "sname"), each tagged with its
        source area and position.
    :param values: concatenated value of each option code following RFC 3396.
        Truncated fragments are excluded and reported in ``errors`` instead.
    :param overload: the effective value of option 52, or ``None`` when the
        message does not declare any overloaded area.
    :param errors: human-readable descriptions of the malformed fragments.
    """
    __slots__ = ["fragments", "values", "overload", "errors"]

    def __init__(self, fragments=None, values=None, overload=None,
                 errors=None):
        self.fragments = fragments or []
        self.values = values or {}
        self.overload = overload
        self.errors = errors or []

    def __repr__(self):
        return "DHCPOptionsAudit(overload=%r, values=%r, errors=%r)" % (
            self.overload, self.values, self.errors)


class RandDHCPOptions(RandField):
    def __init__(self, size=None, rndstr=None):
        if size is None:
            size = RandNumExpo(0.05)
        self.size = size
        if rndstr is None:
            rndstr = RandBin(RandNum(0, 255))
        self.rndstr = rndstr
        self._opts = list(DHCPOptions.values())
        self._opts.remove("pad")
        self._opts.remove("end")

    def _fix(self):
        op = []
        for k in range(self.size):
            o = random.choice(self._opts)
            if isinstance(o, str):
                op.append((o, self.rndstr * 1))
            else:
                r = o.randval()._fix()
                if isinstance(r, bytes):
                    r = r[:255]
                op.append((o.name, r))
        return op

    def __iter__(self):
        return iter(self._fix())


class DHCPOptionsField(StrField):
    """
    A field that builds and dissects DHCP options.
    The internal value is a list of tuples with the format
    [("option_name", <option_value>), ...]
    Where expected names and values can be found using `DHCPOptions`
    """
    islist = 1

    def i2repr(self, pkt, x):
        s = []
        for v in x:
            if isinstance(v, tuple) and len(v) >= 2:
                if v[0] in DHCPRevOptions and isinstance(DHCPRevOptions[v[0]][1], Field):  # noqa: E501
                    f = DHCPRevOptions[v[0]][1]
                    vv = ",".join(f.i2repr(pkt, val) for val in v[1:])
                else:
                    vv = ",".join(repr(val) for val in v[1:])
                s.append("%s=%s" % (v[0], vv))
            else:
                s.append(sane(bytes_encode(v)))
        return "[%s]" % (" ".join(s))

    def getfield(self, pkt, s):
        return b"", self.m2i(pkt, s)

    def m2i(self, pkt, x):
        opt = []
        while x:
            o = x[0]
            if o == 255:
                opt.append("end")
                x = x[1:]
                continue
            if o == 0:
                opt.append("pad")
                x = x[1:]
                continue
            if len(x) < 2 or len(x) < x[1] + 2:
                opt.append(x)
                break
            elif o in DHCPOptions:
                f = DHCPOptions[o]

                if isinstance(f, str):
                    olen = x[1]
                    opt.append((f, x[2:olen + 2]))
                    x = x[olen + 2:]
                else:
                    olen = x[1]
                    lval = [f.name]

                    if olen == 0:
                        try:
                            _, val = f.getfield(pkt, b'')
                        except Exception:
                            opt.append(x)
                            break
                        else:
                            lval.append(val)

                    try:
                        left = x[2:olen + 2]
                        while left:
                            left, val = f.getfield(pkt, left)
                            lval.append(val)
                    except Exception:
                        opt.append(x)
                        break
                    else:
                        otuple = tuple(lval)
                    opt.append(otuple)
                    x = x[olen + 2:]
            else:
                olen = x[1]
                opt.append((o, x[2:olen + 2]))
                x = x[olen + 2:]
        return opt

    def i2m(self, pkt, x):
        if isinstance(x, str):
            return x
        s = b""
        for o in x:
            if isinstance(o, tuple) and len(o) >= 2:
                name = o[0]
                lval = o[1:]

                if isinstance(name, int):
                    onum, oval = name, b"".join(lval)
                elif name in DHCPRevOptions:
                    onum, f = DHCPRevOptions[name]
                    if f is not None:
                        lval = (f.addfield(pkt, b"", f.any2i(pkt, val)) for val in lval)  # noqa: E501
                    else:
                        lval = (bytes_encode(x) for x in lval)
                    oval = b"".join(lval)
                else:
                    warning("Unknown field option %s", name)
                    continue

                s += struct.pack("!BB", onum, len(oval))
                s += oval

            elif (isinstance(o, str) and o in DHCPRevOptions and
                  DHCPRevOptions[o][1] is None):
                s += chb(DHCPRevOptions[o][0])
            elif isinstance(o, int):
                s += chb(o) + b"\0"
            elif isinstance(o, (str, bytes)):
                s += bytes_encode(o)
            else:
                warning("Malformed option %s", o)
        return s

    def randval(self):
        return RandDHCPOptions()


def dhcp_option_name(option):
    # type: (int) -> object
    """
    Return the symbolic name of a DHCP option code, or the numeric code
    itself when it is not known.
    """
    field = DHCPOptions.get(option)
    if isinstance(field, str):
        return field
    if field is not None:
        return field.name
    return option


def dhcp_parse_option_area(data, source):
    # type: (bytes, str) -> Tuple[List[DHCPOptionFragment], List[str]]
    """
    Parse one option area (the main options area or an overloaded "file" or
    "sname" field) into option fragments.

    Parsing stops at the first END option (code 255); data following it is
    treated as padding and reported when it is not all PAD bytes (code 0).
    A TLV whose declared length runs past the area is kept as a truncated
    fragment and reported instead of being read across the area boundary.
    """
    fragments = []
    errors = []
    position = 0
    end_seen = False
    while data:
        option = data[0]
        if option == 255:
            end_seen = True
            data = data[1:]
            position += 1
            break
        if option == 0:
            data = data[1:]
            position += 1
            continue
        if len(data) < 2 or len(data) < data[1] + 2:
            declared = data[1] if len(data) >= 2 else 0
            available = max(len(data) - 2, 0)
            fragments.append(
                DHCPOptionFragment(
                    option, dhcp_option_name(option), data[2:], source,
                    position, truncated=True))
            errors.append(
                "truncated option %s in %r area at position %d: "
                "declared length %d, %d byte(s) available"
                % (dhcp_option_name(option), source, position,
                   declared, available))
            break
        length = data[1]
        value = data[2:length + 2]
        fragments.append(
            DHCPOptionFragment(
                option, dhcp_option_name(option), value, source, position))
        data = data[length + 2:]
        position += length + 2
    if end_seen:
        padding = data
        if padding.strip(b"\x00"):
            errors.append(
                "data after END option in %r area: %r" % (source, padding))
    elif fragments and not fragments[-1].truncated:
        errors.append("missing END option in %r area" % source)
    return fragments, errors


def dhcp_options_audit(pkt):
    # type: (DHCP) -> DHCPOptionsAudit
    """
    Audit the DHCP options of a dissected packet, including the options
    carried in the BOOTP "file" and "sname" fields through option 52
    (DHCP Option Overload, RFC 2132 section 9.3).

    Every option TLV is returned as a separate :class:`DHCPOptionFragment`
    tagged with its source area and position, so duplicate options stay
    visible in the protocol order: main options area first, then "file",
    then "sname" (RFC 3396 section 4). The fragments of each option code are
    also concatenated (RFC 3396 section 3) in ``DHCPOptionsAudit.values``.

    Areas are only read when option 52 declares them overloaded: without the
    declaration, option-like bytes in "file" or "sname" are boot file or
    server name data and are never interpreted as options.
    """
    fragments = []
    errors = []

    main_data = pkt.original
    if not isinstance(main_data, bytes):
        main_data = b""
    main_fragments, main_errors = dhcp_parse_option_area(
        main_data, DHCP_OPTION_AREA_OPTIONS)
    fragments.extend(main_fragments)
    errors.extend(main_errors)

    overload = None
    overload_conflict = False
    overload_fragments = [
        fragment for fragment in main_fragments if fragment.option == 52]
    for fragment in overload_fragments:
        if len(fragment.value) != 1:
            errors.append(
                "invalid dhcp-option-overload value: %r" % (fragment.value,))
            continue
        value = fragment.value[0]
        if value not in DHCP_OVERLOAD_VALUES:
            errors.append(
                "invalid dhcp-option-overload value: %d" % value)
            continue
        if overload is None:
            overload = value
        elif overload != value:
            overload_conflict = True
            errors.append(
                "conflicting dhcp-option-overload values: %d and %d"
                % (overload, value))
    if overload_conflict:
        # Fall back to the widest valid declaration so that each overloaded
        # area is still audited; the conflict remains visible in errors.
        for fragment in overload_fragments:
            if (len(fragment.value) == 1
                    and fragment.value[0] in DHCP_OVERLOAD_VALUES):
                overload |= fragment.value[0]

    bootp = pkt.underlayer if isinstance(pkt.underlayer, BOOTP) else None
    if overload is not None and bootp is None:
        errors.append(
            "dhcp-option-overload declared but no BOOTP layer is available")

    if bootp is not None and overload is not None:
        # RFC 3396 section 4: the "file" area is interpreted before "sname".
        if overload in (DHCP_OVERLOAD_FILE, DHCP_OVERLOAD_BOTH):
            area_fragments, area_errors = dhcp_parse_option_area(
                bootp.file, DHCP_OPTION_AREA_FILE)
            fragments.extend(area_fragments)
            errors.extend(area_errors)
        if overload in (DHCP_OVERLOAD_SNAME, DHCP_OVERLOAD_BOTH):
            area_fragments, area_errors = dhcp_parse_option_area(
                bootp.sname, DHCP_OPTION_AREA_SNAME)
            fragments.extend(area_fragments)
            errors.extend(area_errors)

    values = {}
    for fragment in fragments:
        if fragment.truncated:
            continue
        name = fragment.name
        if name in values:
            values[name] += fragment.value
        else:
            values[name] = fragment.value

    return DHCPOptionsAudit(
        fragments=fragments, values=values, overload=overload,
        errors=errors)


class DHCP(Packet):
    name = "DHCP options"
    fields_desc = [DHCPOptionsField("options", b"")]

    def mysummary(self):
        for id in self.options:
            if isinstance(id, tuple) and id[0] == "message-type":
                return "DHCP %s" % DHCPTypes.get(id[1], "").capitalize()
        return super(DHCP, self).mysummary()

    def getopt(self, name: str):
        try:
            if not self.options:
                raise StopIteration
            return next(x[1] for x in self.options if x[0] == name)
        except StopIteration:
            raise AttributeError("Option '%s' not found !" % name)

    def addopt(self, name: str, value):
        opts = self.options
        if not isinstance(opts, list):
            opts = []
        opts.insert(len(opts) - 1, (name, value))
        self.options = opts

    def options_audit(self):
        # type: () -> DHCPOptionsAudit
        """
        Audit every DHCP option TLV, including duplicate options and the
        options carried in the overloaded BOOTP "file" and "sname" fields.
        See :func:`dhcp_options_audit`.
        """
        return dhcp_options_audit(self)


bind_layers(UDP, BOOTP, dport=67, sport=68)
bind_layers(UDP, BOOTP, dport=68, sport=67)
bind_bottom_up(UDP, BOOTP, dport=67, sport=67)
bind_layers(BOOTP, DHCP, options=b'c\x82Sc')


def _dhcp_query(
    req_type: str,
    hw=None,
    dstip=None,
    ciaddr=None,
    server_id=None,
    requested_addr=None,
    fixed_ether=False,
    hostname=None,
    iface=None,
    wait_resp=True,
    **kwargs,
):
    # We need to set checkIPaddr to False for DHCP
    _old_checkIPaddr = conf.checkIPaddr
    conf.checkIPaddr = False

    try:
        if hw is None:
            if iface is None:
                iface = conf.iface
            hw = get_if_hwaddr(iface)

        # Build the DHCP options of the request
        dhcp_options = [
            ('message-type', req_type),
            ('client_id', b'\x01' + mac2str(hw)),
        ]
        if requested_addr is not None:
            dhcp_options.append(('requested_addr', requested_addr))
        if server_id is not None:
            dhcp_options.append(('server_id', server_id))
        if hostname is not None:
            dhcp_options.extend([
                ('hostname', hostname),
                ('client_FQDN', b'\x00\x00\x00' + bytes_encode(hostname)),
            ])
        dhcp_options.extend([
            ('vendor_class_id', b'MSFT 5.0'),
            ('param_req_list', [
                1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252
            ]),
            'end'
        ])

        # Build the packet
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=None if fixed_ether else hw) /
            IP(
                src=ciaddr or "0.0.0.0",
                dst=dstip or "255.255.255.255",
            ) /
            UDP(sport=68, dport=67) /
            BOOTP(
                chaddr=hw,
                ciaddr=ciaddr or "0.0.0.0",
                xid=RandInt(),
                flags="B",
            ) /
            DHCP(options=dhcp_options)
        )

        if wait_resp:
            return srp1(pkt, iface=iface, **kwargs)
        else:
            return sendp(pkt, iface=iface, **kwargs)
    finally:
        conf.checkIPaddr = _old_checkIPaddr


@conf.commands.register
def dhcp_discover(
    hw=None,
    requested_addr=None,
    hostname=None,
    iface=None,
    **kwargs,
):
    """
    Send a DHCP discover and return the answer

    :param hw: (optional) the source MAC
    :param requested_addr: (optional) ask the DHCP server for a preferred IP
    :param hostname: the hostname of the client (default: not specified)
    :param iface: the interface to send this on. (default: conf.iface)

    Usage::

        >>> dhcp_discover()
    """
    return _dhcp_query(
        req_type="discover",
        hw=hw,
        requested_addr=requested_addr,
        hostname=hostname,
        iface=iface,
        **kwargs,
    )


@conf.commands.register
def dhcp_request(
    requested_addr: str,
    hw=None,
    server_id=None,
    hostname=None,
    iface=None,
    fixed_ether=False,
    **kwargs,
):
    """
    Send a DHCP discover request and return the answer.

    :param server_id: the server id from the OFFER
    :param hw: (optional) the source MAC
    :param requested_addr: request an IP from the DHCP server
    :param hostname: the hostname of the client (default: not specified)
    :param iface: the interface to send this on. (default: conf.iface)
    :param fixed_ether: (optional) use the real local mac in the Ethernet layer,
        and only use 'hw' in the ARP layer.

    Usage::

        >>> srv = dhcp_discover()
        >>> dhcp_request(
        ...    requested_addr=srv.yiaddr,
        ...    server_id=srv[DHCP].getopt("server_id")
        ... )
    """
    return _dhcp_query(
        req_type="request",
        hw=hw,
        server_id=server_id,
        requested_addr=requested_addr,
        hostname=hostname,
        iface=iface,
        fixed_ether=fixed_ether,
        **kwargs,
    )


@conf.commands.register
def dhcp_release(
    ciaddr: str,
    server_id: str,
    hw=None,
    hostname=None,
    iface=None,
    fixed_ether=False,
    **kwargs,
):
    """
    Send a DHCP release request

    :param server_id: the server id from the OFFER
    :param ciaddr: the IP to release
    :param hw: (optional) the source MAC
    :param hostname: the hostname of the client (default: not specified)
    :param iface: the interface to send this on. (default: conf.iface)
    :param fixed_ether: (optional) use the real local mac in the Ethernet layer,
        and only use 'hw' in the ARP layer.

    Usage::

        >>> dhcp_release(ciaddr="10.0.0.12", server_id="10.0.0.254")
    """
    return _dhcp_query(
        req_type="release",
        hw=hw,
        dstip=server_id,
        server_id=server_id,
        ciaddr=ciaddr,
        hostname=hostname,
        iface=iface,
        fixed_ether=fixed_ether,
        wait_resp=False,
        **kwargs,
    )


@conf.commands.register
def dhcp_inform(
    ciaddr: str,
    hw=None,
    hostname=None,
    iface=None,
    fixed_ether=False,
    **kwargs,
):
    """
    Send a DHCP inform request

    :param ciaddr: the IP to inform
    :param hw: (optional) the source MAC
    :param hostname: the hostname of the client (default: not specified)
    :param iface: the interface to send this on. (default: conf.iface)
    :param fixed_ether: (optional) use the real local mac in the Ethernet layer,
        and only use 'hw' in the ARP layer.

    Usage::

        >>> dhcp_inform(ciaddr="10.0.0.12")
    """
    return _dhcp_query(
        req_type="inform",
        hw=hw,
        ciaddr=ciaddr,
        hostname=hostname,
        iface=iface,
        fixed_ether=fixed_ether,
        **kwargs,
    )


class BOOTP_am(AnsweringMachine):
    function_name = "bootpd"
    filter = "udp and port 68 and port 67"

    def parse_options(self,
                      pool: Union[Net, List[str]] = Net("192.168.1.128/25"),
                      network: str = "192.168.1.0/24",
                      gw: str = "192.168.1.1",
                      nameserver: Union[str, List[str]] = None,
                      domain: Optional[str] = None,
                      renewal_time: int = 60,
                      lease_time: int = 1800,
                      **kwargs):
        """
        :param pool: the range of addresses to distribute. Can be a Net,
                     a list of IPs or a string (always gives the same IP).
        :param network: the subnet range
        :param gw: the gateway IP (can be None)
        :param nameserver: the DNS server IP (by default, same than gw).
            This can also be a list.
        :param domain: the domain to advertise (can be None)

        Other DHCP parameters can be passed as kwargs. See DHCPOptions in dhcp.py.
        For instance::

            dhcpd(pool=Net("10.0.10.0/24"), network="10.0.0.0/8", gw="10.0.10.1",
                  classless_static_routes=["1.2.3.4/32:9.8.7.6"])

        Other example with different options::

            dhcpd(pool=Net("10.0.10.0/24"), network="10.0.0.0/8", gw="10.0.10.1",
                  nameserver=["8.8.8.8", "4.4.4.4"], domain="DOMAIN.LOCAL")
        """
        self.domain = domain
        netw, msk = (network.split("/") + ["32"])[:2]
        msk = itom(int(msk))
        self.netmask = ltoa(msk)
        self.network = ltoa(atol(netw) & msk)
        self.broadcast = ltoa(atol(self.network) | (0xffffffff & ~msk))
        self.gw = gw
        if nameserver is None:
            self.nameserver = (gw,)
        elif isinstance(nameserver, str):
            self.nameserver = (nameserver,)
        else:
            self.nameserver = tuple(nameserver)

        if isinstance(pool, str):
            pool = Net(pool)
        if isinstance(pool, Iterable):
            pool = [k for k in pool if k not in [gw, self.network, self.broadcast]]
            pool.reverse()
        if len(pool) == 1:
            pool, = pool
        self.pool = pool
        self.lease_time = lease_time
        self.renewal_time = renewal_time
        self.leases = {}
        self.kwargs = kwargs

    def is_request(self, req):
        if not req.haslayer(BOOTP):
            return 0
        reqb = req.getlayer(BOOTP)
        if reqb.op != 1:
            return 0
        return 1

    def print_reply(self, _, reply):
        print("Reply %s to %s" % (reply.getlayer(IP).dst, reply.dst))

    def make_reply(self, req):
        mac = req[Ether].src
        if isinstance(self.pool, list):
            if mac not in self.leases:
                if not self.pool:
                    return None
                self.leases[mac] = self.pool.pop()
            ip = self.leases[mac]
        else:
            ip = self.pool

        repb = req.getlayer(BOOTP).copy()
        repb.op = "BOOTREPLY"
        repb.yiaddr = ip
        repb.siaddr = self.gw
        repb.ciaddr = self.gw
        repb.giaddr = self.gw
        del repb.payload
        rep = Ether(dst=mac) / IP(dst=ip) / UDP(sport=req.dport, dport=req.sport) / repb  # noqa: E501
        return rep


class DHCP_am(BOOTP_am):
    function_name = "dhcpd"

    def make_reply(self, req):
        resp = BOOTP_am.make_reply(self, req)
        if DHCP in req:
            dhcp_options = [
                (op[0], {1: 2, 3: 5}.get(op[1], op[1]))
                for op in req[DHCP].options
                if isinstance(op, tuple) and op[0] == "message-type"
            ]
            dhcp_options += [
                x for x in [
                    ("server_id", self.gw),
                    ("domain", self.domain),
                    ("router", self.gw),
                    ("name_server", *self.nameserver),
                    ("broadcast_address", self.broadcast),
                    ("subnet_mask", self.netmask),
                    ("renewal_time", self.renewal_time),
                    ("lease_time", self.lease_time),
                ]
                if x[1] is not None
            ]
            if self.kwargs:
                dhcp_options += self.kwargs.items()
            dhcp_options.append("end")
            resp /= DHCP(options=dhcp_options)
        return resp
