"""Self-contained reproducer: offline IKEv2 bytes -> selector sets.

Run from the repository root:

    python examples/ikev2_tsaudit/reproduce.py

The script builds a request/response pair in memory, prints the hex of both
messages, and then compares the visible TSi/TSr sets.  It does not need a
capture file and never touches the network.

To use captured bytes instead, write each IKEv2 message (without UDP/IP
headers) as hex to a file and run:

    python -m scapy.tools.ikev2_tsaudit request.hex response.hex
"""
import ipaddress
import struct

from scapy.contrib.ikev2 import (
    IKEv2, IKEv2_Proposal, IKEv2_SA, IKEv2_TSi, IKEv2_TSr,
    IKEv2_Transform, IPv4TrafficSelector)
from scapy.packet import raw
from scapy.tools.ikev2_tsaudit import (
    Ikev2TSAuditEvidence, Ikev2TSAuditPoint, Ikev2TSAuditRange,
    Ikev2TSAuditSelector, ikev2_tsaudit_assess, ikev2_tsaudit_coverage,
    ikev2_tsaudit_flow, ikev2_tsaudit_flow_matches, ikev2_tsaudit_narrow,
    ikev2_tsaudit_parse_message, ikev2_tsaudit_render)


def ts4(proto, start_port, end_port, start, end):
    return IPv4TrafficSelector(
        TS_type=7, IP_protocol_ID=proto, length=16,
        start_port=start_port, end_port=end_port,
        starting_address_v4=start, ending_address_v4=end)


def child(message_id, flags, spi, tsi, tsr):
    proposal = IKEv2_Proposal(
        next_payload="TSi", proposal=1, proto="ESP", SPI=spi,
        trans=IKEv2_Transform(next_payload="Transform", transform_type=1,
                              transform_id=12) /
              IKEv2_Transform(next_payload=0, transform_type=3,
                              transform_id=12))
    packet = (IKEv2(init_SPI=b"\x01" * 8, resp_SPI=b"\x02" * 8,
                    next_payload="SA", exch_type="CREATE_CHILD_SA",
                    flags=flags, id=message_id) /
              IKEv2_SA(next_payload="TSi", prop=proposal) /
              IKEv2_TSi(next_payload="TSr", traffic_selector=tsi) /
              IKEv2_TSr(next_payload=0, traffic_selector=tsr))
    return raw(packet)


def selector(proto, start, end, start_port, end_port):
    return Ikev2TSAuditSelector(
        4, proto,
        Ikev2TSAuditRange(int(ipaddress.IPv4Address(start)),
                          int(ipaddress.IPv4Address(end))),
        Ikev2TSAuditRange(start_port, end_port))


request_bytes = child(
    42, "Initiator", b"\x11" * 4,
    [ts4(6, 1024, 65535, "10.0.0.0", "10.0.0.255"),
     ts4(17, 53, 53, "10.0.1.0", "10.0.1.255")],
    [ts4(6, 1, 65535, "192.168.1.0", "192.168.1.255")])
response_bytes = child(
    42, "Response", b"\x22" * 4,
    [ts4(6, 20000, 40000, "10.0.0.64", "10.0.0.127"),
     ts4(17, 53, 53, "10.0.1.10", "10.0.1.10")],
    [ts4(6, 443, 443, "192.168.1.10", "192.168.1.10")])

print("request hex :", request_bytes.hex())
print("response hex:", response_bytes.hex())

request = ikev2_tsaudit_parse_message(request_bytes)
response = ikev2_tsaudit_parse_message(response_bytes)
narrowing = ikev2_tsaudit_narrow(request, response)

target_source = selector(6, "10.0.0.0", "10.0.0.255", 1024, 65535)
target_destination = selector(6, "192.168.1.0", "192.168.1.255", 1, 65535)
coverage = ikev2_tsaudit_coverage(
    narrowing, target_source, target_destination)

flows = [
    ikev2_tsaudit_flow(6, "10.0.0.100", 33333, "192.168.1.10", 443),
    ikev2_tsaudit_flow(6, "10.0.0.10", 443, "192.168.1.10", 443),
    ikev2_tsaudit_flow(17, "10.0.1.10", 53, "192.168.1.10", 443),
    ikev2_tsaudit_flow(6, "192.168.1.10", 443, "10.0.0.100", 33333),
]
evidence = Ikev2TSAuditEvidence(
    cleartext_selectors=True,
    esp_headers=[("10.0.0.100", "192.168.1.10", 0x22222222)])
assessment = ikev2_tsaudit_assess(evidence, [narrowing], coverage)

print()
print(ikev2_tsaudit_render(narrowing, flows, assessment, coverage))

print()
print("== Scapy's own parser on the same bytes ==")
legacy = IKEv2(response_bytes)
print("TSi count field:", legacy[IKEv2_TSi].number_of_TSs,
      "parsed:", len(legacy[IKEv2_TSi].traffic_selector))
print("TSr count field:", legacy[IKEv2_TSr].number_of_TSs,
      "parsed:", len(legacy[IKEv2_TSr].traffic_selector))
print("scapy/contrib/ikev2.py exposes fields only: no set intersection,")
print("no TSi/TSr direction pairing, and no CHILD_SA correlation.")
