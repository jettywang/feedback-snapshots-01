# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Passive WPA/EAPOL-Key 4-way handshake association
# scapy.contrib.status = loads

"""
Passive association of WPA/WPA2 EAPOL-Key four-way handshakes observed in a
wireless capture.

The helpers in this module only correlate frames that are present in the
capture. They never transmit, associate to a network, or attempt to recover a
passphrase. Without the pairwise transient key (PTK) message integrity codes
(MIC) cannot be checked, so the report only states observable relationships:
which frames look like retransmissions, which look like a fresh reconnect, and
which messages of a candidate handshake are missing. It must not be read as
proof that a MIC is valid or that a key was established.
"""

from scapy.compat import plain_str
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL, EAPOL_KEY
from scapy.layers.l2 import CookedLinux, Ether

# Roles / directions
WPA_EAPOL_AP_TO_STA = "AP->STA"
WPA_EAPOL_STA_TO_AP = "STA->AP"
WPA_EAPOL_DIR_UNKNOWN = "unknown"

# Key Information bits kept for the report (IEEE 802.11, EAPOL-Key frame)
WPA_EAPOL_KEY_INFO_FIELDS = (
    "key_descriptor_type_version",
    "key_type",
    "install",
    "key_ack",
    "has_key_mic",
    "secure",
    "error",
    "request",
    "encrypted_key_data",
    "smk_message",
)

# Number of messages in a pairwise four-way handshake
WPA_EAPOL_HANDSHAKE_MESSAGES = (1, 2, 3, 4)


class WpaEapolKeyObservation(object):
    """A single observed pairwise EAPOL-Key frame.

    Only fields readable from the frame itself are stored. The MIC bytes are
    intentionally not interpreted: without the PTK they cannot be validated.
    """

    def __init__(self, index, packet, eapol_key):
        self.index = index
        self.time = float(packet.time) if packet.time is not None else None
        self.key_number = eapol_key.guess_key_number()
        self.replay_counter = eapol_key.key_replay_counter
        self.anonces = eapol_key.key_nonce
        self.key_info = {
            field: eapol_key.getfieldval(field)
            for field in WPA_EAPOL_KEY_INFO_FIELDS
        }
        self.mic_present = eapol_key.has_key_mic == 1
        self.mic_zero = eapol_key.key_mic == (b"\x00" * len(eapol_key.key_mic))
        self.ap_mac, self.sta_mac, self.direction = wpa_eapol_endpoints(packet)
        self.duplicate_of = None
        self.notes = []

    @property
    def pair(self):
        return self.ap_mac, self.sta_mac

    def key_info_text(self):
        return ",".join(
            "%s=%d" % (field, self.key_info[field])
            for field in WPA_EAPOL_KEY_INFO_FIELDS
        )

    def __repr__(self):
        return "<WpaEapolKeyObservation #%d M%s replay=%d %s>" % (
            self.index,
            self.key_number or "?",
            self.replay_counter,
            self.direction,
        )


class WpaHandshakeCandidate(object):
    """A candidate four-way handshake built from observed frames."""

    def __init__(self, candidate_id, ap_mac, sta_mac):
        self.candidate_id = candidate_id
        self.ap_mac = ap_mac
        self.sta_mac = sta_mac
        self.observations = []
        self.gaps = []
        self.notes = []
        self.started_with_m1 = False
        # Replay counter carried by the candidate's message 1. Messages 1/2
        # share this value; messages 3/4 use it incremented by one.
        self.m1_replay = None

    @property
    def messages(self):
        return sorted({
            obs.key_number
            for obs in self.observations
            if obs.key_number in WPA_EAPOL_HANDSHAKE_MESSAGES
        })

    @property
    def retransmissions(self):
        return [obs for obs in self.observations if obs.duplicate_of is not None]

    @property
    def is_complete(self):
        return all(
            number in self.messages
            for number in WPA_EAPOL_HANDSHAKE_MESSAGES
        )

    @property
    def status(self):
        if self.is_complete:
            return "complete (observable messages only; MIC not verified)"
        if not self.started_with_m1:
            return "unpaired (no message 1 observed)"
        return "incomplete (missing: %s)" % ", ".join(
            "M%d" % number
            for number in WPA_EAPOL_HANDSHAKE_MESSAGES
            if number not in self.messages
        )

    def add(self, observation):
        self.observations.append(observation)

    def finalize(self):
        seen = set()
        for obs in self.observations:
            if obs.key_number in WPA_EAPOL_HANDSHAKE_MESSAGES:
                seen.add(obs.key_number)
        self.gaps = [
            number
            for number in WPA_EAPOL_HANDSHAKE_MESSAGES
            if number not in seen
        ]


class WpaHandshakeReport(object):
    """Result of a passive EAPOL-Key four-way handshake correlation."""

    def __init__(self):
        self.candidates = []
        self.ignored_eapol_frames = 0
        self.notes = [
            "Passive analysis of captured frames only; no frame was sent and "
            "no association was attempted.",
            "No PTK available: message MICs are not verified and key "
            "establishment is not claimed.",
        ]

    def summary(self):
        complete = sum(1 for cand in self.candidates if cand.is_complete)
        return (
            "%d candidate handshake(s): %d complete, %d incomplete "
            "(observable messages only)"
        ) % (
            len(self.candidates),
            complete,
            len(self.candidates) - complete,
        )

    def show(self):
        print(self.render_text())

    def render_text(self):
        lines = ["WPA/EAPOL-Key four-way handshake passive report",
                 self.summary(),
                 ""]
        for note in self.notes:
            lines.append("NOTE: %s" % note)
        for cand in self.candidates:
            lines.append("")
            lines.append(
                "Candidate %d: AP %s <-> STA %s - %s"
                % (cand.candidate_id, cand.ap_mac, cand.sta_mac, cand.status)
            )
            if cand.gaps:
                lines.append("  gaps: %s" % ", ".join(
                    "M%d" % number for number in cand.gaps))
            for obs in cand.observations:
                role = (
                    "retransmission of frame #%s" % obs.duplicate_of
                    if obs.duplicate_of is not None
                    else "first observation"
                )
                lines.append(
                    "  frame #%d t=%s M%s replay=%d nonce=%s %s [%s] (%s)"
                    % (
                        obs.index,
                        obs.time,
                        obs.key_number or "?",
                        obs.replay_counter,
                        obs.anonces[:8].hex() or "empty",
                        obs.direction,
                        obs.key_info_text(),
                        role,
                    )
                )
                for note in obs.notes:
                    lines.append("    - %s" % note)
            for note in cand.notes:
                lines.append("  note: %s" % note)
        return "\n".join(lines)


def wpa_eapol_mac_normalize(mac):
    """Return a MAC address as a lowercase string, or None."""
    if mac is None or not mac:
        return None
    mac = plain_str(mac)
    if mac == "00:00:00:00:00:00":
        return None
    return mac.lower()


def wpa_eapol_endpoints(packet):
    """Return ``(ap_mac, sta_mac, direction)`` for a frame carrying EAPOL.

    802.11 data frames are classified with the ToDS/FromDS flags. Plain
    Ethernet/SLL captures fall back to the link-layer addresses and the
    EAPOL-Key ``key_ack`` bit.
    """
    dot11 = packet.getlayer(Dot11)
    if dot11 is not None:
        to_ds = dot11.FCfield & 0x1 != 0
        from_ds = dot11.FCfield & 0x2 != 0
        addr1 = wpa_eapol_mac_normalize(dot11.addr1)
        addr2 = wpa_eapol_mac_normalize(dot11.addr2)
        addr3 = wpa_eapol_mac_normalize(dot11.addr3)
        if to_ds and not from_ds:
            # STA -> AP: addr1 = BSSID/AP, addr2 = STA
            return addr1, addr2, WPA_EAPOL_STA_TO_AP
        if from_ds and not to_ds:
            # AP -> STA: addr1 = STA, addr2 = BSSID/AP
            return addr2, addr1, WPA_EAPOL_AP_TO_STA
        if from_ds and to_ds:
            # Wireless distribution system: addr3 is the destination AP
            ap_mac = addr3
            sta_mac = addr2 if addr2 != ap_mac else addr1
            return ap_mac, sta_mac, WPA_EAPOL_DIR_UNKNOWN
        return addr2, addr1, WPA_EAPOL_DIR_UNKNOWN

    for layer in (Ether, CookedLinux):
        link = packet.getlayer(layer)
        if link is not None:
            src = wpa_eapol_mac_normalize(getattr(link, "src", None))
            dst = wpa_eapol_mac_normalize(getattr(link, "dst", None))
            break
    else:
        return None, None, WPA_EAPOL_DIR_UNKNOWN

    eapol_key = packet[EAPOL_KEY]
    if eapol_key.key_ack == 1:
        # Messages 1 and 3 are sent by the authenticator (AP)
        return src, dst, WPA_EAPOL_AP_TO_STA
    return dst, src, WPA_EAPOL_STA_TO_AP


def wpa_eapol_is_pairwise_key(packet):
    """Check that the packet carries a pairwise EAPOL-Key frame."""
    eapol = packet.getlayer(EAPOL)
    if eapol is None or eapol.type != EAPOL.KEY:
        return False
    eapol_key = packet.getlayer(EAPOL_KEY)
    return eapol_key is not None and eapol_key.key_type == 1


def wpa_eapol_observations(packets):
    """Extract pairwise EAPOL-Key observations from a packet list in order."""
    observations = []
    for index, packet in enumerate(packets):
        if wpa_eapol_is_pairwise_key(packet):
            observations.append(
                WpaEapolKeyObservation(index, packet, packet[EAPOL_KEY])
            )
    return observations


def _wpa_eapol_record_duplicate(candidate, observation):
    """Mark an observation as a retransmission inside a candidate."""
    for previous in candidate.observations:
        if (previous.key_number == observation.key_number
                and previous.replay_counter == observation.replay_counter):
            observation.duplicate_of = previous.index
            if previous.anonces != observation.anonces:
                observation.notes.append(
                    "retransmission carries a different nonce than frame #%d"
                    % previous.index
                )
            return
    # Same replay counter but a message number not yet seen: out of order or
    # an ambiguous frame, keep it observable instead of merging it silently.
    observation.notes.append(
        "same replay counter as an earlier frame but message number M%s "
        "was not seen before" % observation.key_number
    )


def wpa_eapol_associate(packets):
    """Group captured pairwise EAPOL-Key frames into handshake candidates.

    Candidates are keyed on the (AP, STA) identities, direction, replay
    counter, nonce and Key Information. A new message 1 starts a new
    candidate, so a short reconnect between the same devices can never borrow
    frames from the previous attempt to appear complete.

    :param packets: an iterable of dissected packets (e.g. ``rdpcap`` output)
    :return: a :class:`WpaHandshakeReport`
    """
    report = WpaHandshakeReport()
    # One open candidate per (AP, STA) pair
    active = {}

    for index, packet in enumerate(packets):
        if packet.getlayer(EAPOL) is not None and not \
                wpa_eapol_is_pairwise_key(packet):
            # Group/SMK keys and non-Key EAPOL frames are out of scope
            report.ignored_eapol_frames += 1
            continue
        if not wpa_eapol_is_pairwise_key(packet):
            continue
        observation = WpaEapolKeyObservation(index, packet, packet[EAPOL_KEY])
        pair = observation.pair
        candidate = active.get(pair)

        if observation.key_number == 1:
            if (candidate is not None
                    and candidate.m1_replay == observation.replay_counter
                    and 1 in candidate.messages):
                # Same replay counter as the current message 1: retransmission
                _wpa_eapol_record_duplicate(candidate, observation)
            else:
                # Fresh message 1: a new attempt, even for the same MAC pair
                if candidate is not None:
                    candidate.notes.append(
                        "closed by a new message 1 at frame #%d; the next "
                        "reconnect is tracked separately" % observation.index
                    )
                    candidate.finalize()
                candidate = WpaHandshakeCandidate(
                    len(report.candidates) + 1,
                    observation.ap_mac,
                    observation.sta_mac,
                )
                candidate.started_with_m1 = True
                candidate.m1_replay = observation.replay_counter
                report.candidates.append(candidate)
                active[pair] = candidate
            candidate.add(observation)
            continue

        if candidate is None:
            # No message 1 in the capture for this pair: do not graft the
            # frame onto another attempt, keep it in its own unpaired group
            candidate = WpaHandshakeCandidate(
                len(report.candidates) + 1,
                observation.ap_mac,
                observation.sta_mac,
            )
            candidate.notes.append(
                "no message 1 observed before frame #%d; cannot attach it "
                "to another handshake" % observation.index
            )
            report.candidates.append(candidate)
            active[pair] = candidate
        elif candidate.m1_replay is not None:
            expected_replay = candidate.m1_replay + (
                1 if observation.key_number in (3, 4) else 0
            )
            if observation.replay_counter != expected_replay:
                observation.notes.append(
                    "replay counter %d does not follow the message 1 value "
                    "%d (expected %d for M%s); treated as observable only"
                    % (
                        observation.replay_counter,
                        candidate.m1_replay,
                        expected_replay,
                        observation.key_number,
                    )
                )

        if observation.key_number in candidate.messages:
            _wpa_eapol_record_duplicate(candidate, observation)
        candidate.add(observation)

    for candidate in report.candidates:
        candidate.finalize()
        retransmissions = candidate.retransmissions
        if retransmissions:
            candidate.notes.append(
                "%d retransmitted frame(s): %s"
                % (
                    len(retransmissions),
                    ", ".join(
                        "#%d" % obs.index for obs in retransmissions
                    ),
                )
            )
        if not candidate.started_with_m1 and 1 in candidate.gaps:
            candidate.notes.append(
                "message 1 missing: the start of the handshake is not in "
                "this capture"
            )
    return report
