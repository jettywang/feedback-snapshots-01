"""Offline forensic reassembly of EAP-TLS (RFC 5216) carried in RADIUS.

Read-only component built on pyrad: it decodes captured RADIUS packets,
verifies them against a test shared secret and reassembles the TLS byte
streams carried by EAP-Message attributes (RFC 3579). It never opens a
socket and never contacts a RADIUS server.

Pipeline:

1. Every packet is decoded and verified first (Message-Authenticator for
   Access-Request, Response Authenticator + Message-Authenticator for
   replies matched to their request). Packets that fail verification are
   excluded from reassembly.
2. EAP-Message attributes of each packet are concatenated in their
   original order and the EAP-TLS conversation is reassembled per
   session and direction, honouring the L/M/S flags, the TLS Message
   Length, fragment acknowledgements, EAP Identifiers and the State
   attribute. Retransmissions are never appended twice; missing or
   reordered packets are reported, never guessed.

Scope limit: verified RADIUS packets and complete TLS bytes only show
transport integrity. Whether the client certificate chain or the TLS
Finished messages are valid cannot be decided by this offline
reassembly.
"""

import enum
import hashlib
import struct
from dataclasses import dataclass, field

from pyrad import packet as radius_packet
from pyrad.packet import PacketError

# RADIUS attribute codes (used without a dictionary, values stay raw).
USER_NAME_ATTR = 1
NAS_PORT_ATTR = 5
STATE_ATTR = 24
CALLING_STATION_ID_ATTR = 31
EAP_MESSAGE_ATTR = 79

# EAP codes (RFC 3748).
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_TYPE_TLS = 13

# EAP-TLS flags (RFC 5216 section 2.1.1).
FLAG_LENGTH_INCLUDED = 0x80
FLAG_MORE_FRAGMENTS = 0x40
FLAG_START = 0x20

DISCLAIMER = (
    'RADIUS 验真通过且 TLS 字节重组完整，仅说明传输字节可归属、无缺失；'
    '不代表已验证客户端证书链或 TLS Finished。离线重组无法校验证书有效性、'
    '握手签名与密钥协商，这些需要额外的 TLS 握手分析。'
)

_CODE_NAMES = {
    radius_packet.AccessRequest: 'Access-Request',
    radius_packet.AccessAccept: 'Access-Accept',
    radius_packet.AccessReject: 'Access-Reject',
    radius_packet.AccessChallenge: 'Access-Challenge',
}

_REPLY_CODES = (
    radius_packet.AccessAccept,
    radius_packet.AccessReject,
    radius_packet.AccessChallenge,
)


class Direction(enum.Enum):
    PEER_TO_SERVER = 'peer→server'
    SERVER_TO_PEER = 'server→peer'


class Verification(enum.Enum):
    VERIFIED = 'verified'
    FAILED = 'failed'
    UNVERIFIABLE = 'unverifiable'


class MessageStatus(enum.Enum):
    COMPLETE = 'complete'
    TRUNCATED = 'truncated'
    UNATTRIBUTABLE = 'unattributable'


@dataclass
class CapturedPacket:
    """One captured RADIUS packet and its receive time (input)."""

    raw: bytes
    received_at: float


@dataclass
class AttrSpan:
    """Byte range [start, end) of one EAP-Message attribute in a packet."""

    ordinal: int
    start: int
    end: int


@dataclass
class Segment:
    """Contiguous recovered bytes with their provenance."""

    packet_index: int
    radius_id: int
    eap_identifier: int
    offset: int | None  # offset in the reassembled message, None if unknown
    data: bytes
    spans: list

    @property
    def length(self):
        return len(self.data)


@dataclass
class TlsMessage:
    """One reassembled (or partially reassembled) EAP-TLS message."""

    index: int
    direction: 'Direction'
    declared_length: int | None
    status: 'MessageStatus'
    segments: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def received(self):
        return sum(seg.length for seg in self.segments)

    def reassembled(self):
        """Return the reassembled bytes, or None if offsets are unknown
        or not contiguous from zero."""
        out = bytearray()
        for seg in self.segments:
            if seg.offset is None or seg.offset != len(out):
                return None
            out += seg.data
        return bytes(out)


@dataclass
class PacketRecord:
    """Forensic record of one captured packet."""

    index: int
    received_at: float
    code: int | None
    radius_id: int | None
    direction: 'Direction | None'
    session_key: tuple | None
    verification: 'Verification'
    notes: list = field(default_factory=list)
    duplicate_of: int | None = None
    eap_summary: str | None = None


@dataclass
class SessionRecord:
    key: tuple | None
    messages: list = field(default_factory=list)
    events: list = field(default_factory=list)


@dataclass
class ReassemblyReport:
    packets: list
    sessions: dict
    events: list
    total_reassembled_bytes: int
    disclaimer: str = DISCLAIMER

    def render(self):
        lines = ['=== RADIUS/EAP-TLS 离线重组报告 ===', '', '包记录（按接收时刻排序）:']
        for rec in self.packets:
            code = _CODE_NAMES.get(rec.code, str(rec.code))
            line = ('  #%d t=%.3f %s id=%s 验真=%s'
                    % (rec.index, rec.received_at, code, rec.radius_id,
                       rec.verification.value))
            if rec.direction is not None:
                line += ' %s' % rec.direction.value
            if rec.session_key is not None:
                line += ' 会话=%r' % (rec.session_key,)
            if rec.duplicate_of is not None:
                line += ' [重复传输，同包#%d]' % rec.duplicate_of
            if rec.eap_summary:
                line += ' | %s' % rec.eap_summary
            lines.append(line)
            for note in rec.notes:
                lines.append('      注意: %s' % note)
        status_label = {
            MessageStatus.COMPLETE: '完整',
            MessageStatus.TRUNCATED: '截断',
            MessageStatus.UNATTRIBUTABLE: '关联不明',
        }
        for key, sess in self.sessions.items():
            lines.append('')
            if key is None:
                lines.append('会话 <关联不明：无法归属到任何会话>:')
            else:
                lines.append('会话 %r:' % (key,))
            for msg in sess.messages:
                declared = ('未知' if msg.declared_length is None
                            else str(msg.declared_length))
                lines.append('  消息#%d %s 状态=%s 声明长度=%s 已重组=%d'
                             % (msg.index, msg.direction.value,
                                status_label[msg.status], declared,
                                msg.received))
                for seg in msg.segments:
                    if seg.offset is None:
                        where = '偏移未知'
                    else:
                        where = '[%d..%d)' % (seg.offset,
                                              seg.offset + seg.length)
                    spans = '+'.join('属性#%d[%d:%d]' % (s.ordinal, s.start, s.end)
                                     for s in seg.spans)
                    lines.append('    段 %s ← 包#%d RADIUS-id=%s EAP-id=%d %s'
                                 % (where, seg.packet_index, seg.radius_id,
                                    seg.eap_identifier, spans))
                for note in msg.notes:
                    lines.append('    注意: %s' % note)
            for event in sess.events:
                lines.append('  事件: %s' % event)
        if self.events:
            lines.append('')
            lines.append('全局事件:')
            for event in self.events:
                lines.append('  %s' % event)
        lines.append('')
        lines.append('重组总字节: %d' % self.total_reassembled_bytes)
        lines.append('免责说明: %s' % self.disclaimer)
        return '\n'.join(lines)


@dataclass
class _ParsedEap:
    code: int
    identifier: int
    eap_type: int | None
    flags: int | None
    tls_length: int | None
    data_offset: int  # offset of TLS data in the concatenated EAP-Message
    data_length: int
    summary: str


@dataclass
class _Stream:
    current: TlsMessage | None = None
    broken: bool = False
    last_data_id: int | None = None


@dataclass
class _SessionState:
    key: tuple | None
    record: SessionRecord | None = None
    streams: dict = field(default_factory=dict)
    seen_eap: set = field(default_factory=set)
    last_state: bytes | None = None
    last_request_eap_id: int | None = None

    def __post_init__(self):
        self.record = SessionRecord(key=self.key)
        self.streams = {
            Direction.PEER_TO_SERVER: _Stream(),
            Direction.SERVER_TO_PEER: _Stream(),
        }


class EapTlsReassembler:
    """Verify captured RADIUS packets and reassemble EAP-TLS messages.

    :param secret: test shared secret used only to verify packets
    :param max_sessions: at most this many sessions are reassembled
    :param max_message_bytes: per-message reassembly cap
    :param max_total_bytes: global reassembly cap over all sessions
    :param require_message_authenticator: also drop packets whose
        authenticity cannot be established (no Message-Authenticator on
        a request, no matching request for a reply); by default they are
        reassembled but flagged UNVERIFIABLE
    """

    def __init__(self, secret, *, max_sessions=64, max_message_bytes=262144,
                 max_total_bytes=4194304, require_message_authenticator=False):
        if not isinstance(secret, bytes):
            raise TypeError('secret must be bytes')
        self._secret = secret
        self.max_sessions = max_sessions
        self.max_message_bytes = max_message_bytes
        self.max_total_bytes = max_total_bytes
        self._require_ma = require_message_authenticator

    def process(self, captures):
        """Run the two-phase pipeline and return a ReassemblyReport.

        :param captures: iterable of CapturedPacket or (raw, received_at)
        """
        self._pending = {}
        self._seen_radius = {}
        self._sessions = {}
        self._events = []
        self._work = {}
        self._packets = {}
        self._total_bytes = 0

        normalized = []
        for item in captures:
            if isinstance(item, CapturedPacket):
                normalized.append(item)
            else:
                raw, received_at = item
                normalized.append(CapturedPacket(raw=raw,
                                                 received_at=received_at))
        ordered = sorted(enumerate(normalized),
                         key=lambda pair: (pair[1].received_at, pair[0]))

        records = []
        for index, (_, cap) in enumerate(ordered):
            records.append(self._decode_and_verify(index, cap))
        for rec in records:
            self._reassemble(rec)
        return self._build_report(records)

    # phase 1: decode and verify

    def _decode_and_verify(self, index, cap):
        rec = PacketRecord(index=index, received_at=cap.received_at,
                           code=None, radius_id=None, direction=None,
                           session_key=None, verification=Verification.FAILED)
        try:
            pkt = radius_packet.Packet(code=0, secret=self._secret,
                                       packet=cap.raw)
        except (PacketError, struct.error) as exc:
            rec.notes.append('RADIUS 解码失败: %s' % exc)
            self._events.append('包#%d 解码失败: %s' % (index, exc))
            return rec

        rec.code = pkt.code
        rec.radius_id = pkt.id
        self._packets[index] = pkt

        radius_key = (pkt.code, pkt.id, pkt.authenticator)
        if radius_key in self._seen_radius:
            rec.duplicate_of = self._seen_radius[radius_key]
            rec.verification = Verification.UNVERIFIABLE
            rec.notes.append('重复传输（与包#%d 相同），不重复处理'
                             % self._seen_radius[radius_key])
            return rec
        self._seen_radius[radius_key] = index

        if pkt.code == radius_packet.AccessRequest:
            rec.direction = Direction.PEER_TO_SERVER
            rec.session_key = self._session_key(pkt)
            self._verify_request(pkt, rec)
            self._pending.setdefault(pkt.id, []).append(
                (pkt, rec.session_key))
        elif pkt.code in _REPLY_CODES:
            rec.direction = Direction.SERVER_TO_PEER
            self._verify_reply(pkt, rec)
        else:
            rec.verification = Verification.UNVERIFIABLE
            rec.notes.append('非认证报文（code=%d），不参与重组' % pkt.code)
            return rec

        chunks = pkt.get(EAP_MESSAGE_ATTR) or []
        if chunks:
            concat, attr_map = _concat_attributes(chunks)
            parsed, anomalies = _parse_eap(concat)
            for anomaly in anomalies:
                rec.notes.append(anomaly)
            if parsed is not None:
                rec.eap_summary = parsed.summary
                self._work[index] = (parsed, concat, attr_map)
        return rec

    def _verify_request(self, pkt, rec):
        if pkt.message_authenticator:
            if pkt.verify_message_authenticator():
                rec.verification = Verification.VERIFIED
            else:
                rec.verification = Verification.FAILED
                rec.notes.append('Message-Authenticator 校验失败')
                self._events.append('包#%d Message-Authenticator 校验失败'
                                    % rec.index)
        else:
            rec.verification = Verification.UNVERIFIABLE
            rec.notes.append('无 Message-Authenticator，无法离线验真')

    def _verify_reply(self, pkt, rec):
        pending = self._pending.get(pkt.id)
        if not pending:
            rec.verification = Verification.UNVERIFIABLE
            rec.notes.append('找不到匹配的请求，无法校验 Response '
                             'Authenticator；字节关联不明')
            return
        request, session_key = pending.pop(0)
        rec.session_key = session_key
        if request.VerifyReply(pkt):
            rec.verification = Verification.VERIFIED
        else:
            rec.verification = Verification.FAILED
            rec.notes.append('Response Authenticator 或 '
                             'Message-Authenticator 校验失败')
            self._events.append('包#%d 应答验真失败' % rec.index)

    @staticmethod
    def _session_key(pkt):
        station = pkt.get(CALLING_STATION_ID_ATTR)
        user = pkt.get(USER_NAME_ATTR)
        nas_port = pkt.get(NAS_PORT_ATTR)
        who = station[0] if station else (user[0] if user else b'unknown')
        port = None
        if nas_port and len(nas_port[0]) == 4:
            port = struct.unpack('!I', nas_port[0])[0]
        return (who, port)

    # phase 2: reassemble

    def _reassemble(self, rec):
        work = self._work.get(rec.index)
        if work is None:
            return
        if rec.verification is Verification.FAILED:
            self._events.append('包#%d 验真失败，其 EAP 数据不参与重组'
                                % rec.index)
            return
        if rec.verification is Verification.UNVERIFIABLE and self._require_ma:
            self._events.append('包#%d 无法验真且策略要求验真，跳过' % rec.index)
            return
        parsed, concat, attr_map = work

        sess = self._session_for(rec)
        if sess is None:
            return

        self._check_direction(rec, parsed, sess)
        self._check_state(rec, sess)
        self._check_identifier(rec, parsed, sess)

        if parsed.code in (EAP_SUCCESS, EAP_FAILURE):
            self._sess_event(sess, rec, 'EAP %s' %
                             ('Success' if parsed.code == EAP_SUCCESS
                              else 'Failure'))
            return
        if parsed.eap_type != EAP_TYPE_TLS:
            self._sess_event(sess, rec, '非 TLS 的 EAP 类型 %r，不重组'
                             % parsed.eap_type)
            return
        self._feed_tls(sess, rec, parsed, concat, attr_map)

    def _session_for(self, rec):
        key = rec.session_key
        if key not in self._sessions:
            if len(self._sessions) >= self.max_sessions:
                self._events.append('包#%d 会话数超过上限 %d，未重组'
                                    % (rec.index, self.max_sessions))
                return None
            self._sessions[key] = _SessionState(key=key)
        return self._sessions[key]

    def _check_direction(self, rec, parsed, sess):
        if rec.direction is Direction.PEER_TO_SERVER \
                and parsed.code != EAP_RESPONSE:
            self._sess_event(sess, rec, '方向异常：peer→server 出现 EAP '
                             'code=%d' % parsed.code)
        if rec.direction is Direction.SERVER_TO_PEER and parsed.code not in \
                (EAP_REQUEST, EAP_SUCCESS, EAP_FAILURE):
            self._sess_event(sess, rec, '方向异常：server→peer 出现 EAP '
                             'code=%d' % parsed.code)

    def _check_state(self, rec, sess):
        pkt_states = self._raw_attr(rec, STATE_ATTR)
        if rec.direction is Direction.SERVER_TO_PEER:
            if pkt_states:
                sess.last_state = pkt_states[-1]
            return
        if pkt_states:
            if sess.last_state is not None \
                    and pkt_states[-1] != sess.last_state:
                self._sess_event(sess, rec, 'State 与服务器上次下发不符，'
                                 '可能缺少中间包')
        elif sess.last_state is not None:
            self._sess_event(sess, rec, '请求缺少 State 属性，可能缺少中间包')

    def _raw_attr(self, rec, code):
        index_pkt = self._packets.get(rec.index)
        if index_pkt is None:
            return []
        return index_pkt.get(code) or []

    def _check_identifier(self, rec, parsed, sess):
        if parsed.code == EAP_REQUEST:
            sess.last_request_eap_id = parsed.identifier
        elif parsed.code == EAP_RESPONSE \
                and sess.last_request_eap_id is not None \
                and parsed.identifier != sess.last_request_eap_id:
            self._sess_event(sess, rec, 'EAP Response Identifier %d 与最近的 '
                             'Request %d 不符，可能丢包或乱序'
                             % (parsed.identifier, sess.last_request_eap_id))

    def _feed_tls(self, sess, rec, parsed, concat, attr_map):
        stream = sess.streams[rec.direction]
        flags = parsed.flags

        if flags & FLAG_START and parsed.data_length == 0:
            self._sess_event(sess, rec, 'EAP-TLS Start（S 标志，无数据）')
            return
        if parsed.data_length == 0:
            self._sess_event(sess, rec, '片段确认（ACK），无 TLS 数据')
            return

        digest = hashlib.sha256(
            concat[parsed.data_offset:
                   parsed.data_offset + parsed.data_length]).digest()
        eap_key = (rec.direction, parsed.code, parsed.identifier, digest)
        if eap_key in sess.seen_eap:
            self._sess_event(sess, rec, '重复的 EAP 片段，不重复追加')
            return
        sess.seen_eap.add(eap_key)

        if flags & FLAG_LENGTH_INCLUDED:
            if stream.current is not None:
                stream.current.status = MessageStatus.TRUNCATED
                stream.current.notes.append('新消息开始时上一消息未收齐')
                self._sess_event(sess, rec, '上一消息未收齐即出现新消息，'
                                 '上一消息标记为截断')
                stream.current = None
            stream.broken = False
            msg = TlsMessage(index=len(sess.record.messages),
                             direction=rec.direction,
                             declared_length=parsed.tls_length,
                             status=MessageStatus.TRUNCATED)
            sess.record.messages.append(msg)
            if parsed.tls_length is not None \
                    and parsed.tls_length > self.max_message_bytes:
                msg.notes.append('声明长度超过单消息上限 %d'
                                 % self.max_message_bytes)
            self._append_segment(sess, msg, rec, parsed, concat, attr_map)
            stream.last_data_id = parsed.identifier
            if flags & FLAG_MORE_FRAGMENTS:
                stream.current = msg
            else:
                self._finish_message(stream, msg)
            return

        if stream.current is not None:
            delta = (parsed.identifier - stream.last_data_id) % 256
            if delta == 1:
                msg = stream.current
                self._append_segment(sess, msg, rec, parsed, concat, attr_map)
                stream.last_data_id = parsed.identifier
                if not (flags & FLAG_MORE_FRAGMENTS):
                    self._finish_message(stream, msg)
            elif delta == 0:
                stream.current.status = MessageStatus.TRUNCATED
                stream.current.notes.append('同一 Identifier 出现不同负载')
                stream.current = None
                stream.broken = True
                self._orphan(sess, rec, parsed, concat, attr_map,
                             '与上一片段 Identifier 相同但负载不同，无法归属')
            else:
                stream.current.status = MessageStatus.TRUNCATED
                stream.current.notes.append(
                    'Identifier 跳变，疑似丢包，后续字节偏移未知')
                stream.current = None
                stream.broken = True
                self._orphan(sess, rec, parsed, concat, attr_map,
                             'Identifier 跳变（疑似丢包），偏移未知，无法归属')
            return

        if stream.broken:
            self._orphan(sess, rec, parsed, concat, attr_map,
                         '消息起始片段缺失，无法归属')
            return

        msg = TlsMessage(index=len(sess.record.messages),
                         direction=rec.direction, declared_length=None,
                         status=MessageStatus.COMPLETE,
                         notes=['未分片消息（无 L 标志），按完整 TLS 消息处理'])
        sess.record.messages.append(msg)
        self._append_segment(sess, msg, rec, parsed, concat, attr_map)

    def _finish_message(self, stream, msg):
        if msg.declared_length is not None \
                and msg.received == msg.declared_length:
            msg.status = MessageStatus.COMPLETE
        else:
            msg.status = MessageStatus.TRUNCATED
            msg.notes.append('末片段已出现但字节数与声明不符（声明 %s，实收 %d）'
                             % (msg.declared_length, msg.received))
        stream.current = None

    def _orphan(self, sess, rec, parsed, concat, attr_map, reason):
        msg = TlsMessage(index=len(sess.record.messages),
                         direction=rec.direction, declared_length=None,
                         status=MessageStatus.UNATTRIBUTABLE, notes=[reason])
        sess.record.messages.append(msg)
        self._append_segment(sess, msg, rec, parsed, concat, attr_map,
                             orphan=True)
        self._sess_event(sess, rec, reason)

    def _append_segment(self, sess, msg, rec, parsed, concat, attr_map,
                        orphan=False):
        begin = parsed.data_offset
        room = min(self.max_message_bytes - msg.received,
                   self.max_total_bytes - self._total_bytes)
        take = max(0, min(parsed.data_length, room))
        if take == 0:
            msg.notes.append('达到字节上限，%d 字节未收录' % parsed.data_length)
            self._sess_event(sess, rec, '字节上限：消息#%d 丢弃 %d 字节'
                             % (msg.index, parsed.data_length))
            return
        spans = _spans_for(attr_map, begin, begin + take)
        msg.segments.append(Segment(
            packet_index=rec.index,
            radius_id=rec.radius_id,
            eap_identifier=parsed.identifier,
            offset=None if orphan else msg.received,
            data=concat[begin:begin + take],
            spans=spans))
        self._total_bytes += take
        if take < parsed.data_length:
            msg.notes.append('达到字节上限，仅收录 %d/%d 字节'
                             % (take, parsed.data_length))

    def _sess_event(self, sess, rec, text):
        sess.record.events.append('包#%d %s' % (rec.index, text))

    def _build_report(self, records):
        return ReassemblyReport(
            packets=records,
            sessions={key: sess.record
                      for key, sess in self._sessions.items()},
            events=list(self._events),
            total_reassembled_bytes=self._total_bytes)


def _concat_attributes(chunks):
    """Concatenate EAP-Message attributes in order, keeping a map from
    concatenated offsets back to (ordinal, start, end) of each attribute."""
    concat = b''
    attr_map = []
    for ordinal, chunk in enumerate(chunks):
        attr_map.append((ordinal, len(concat), len(concat) + len(chunk)))
        concat += chunk
    return concat, attr_map


def _spans_for(attr_map, begin, end):
    spans = []
    for ordinal, start, stop in attr_map:
        lo = max(begin, start)
        hi = min(end, stop)
        if lo < hi:
            spans.append(AttrSpan(ordinal=ordinal,
                                  start=lo - start, end=hi - start))
    return spans


def _parse_eap(concat):
    """Parse one EAP packet from concatenated EAP-Message bytes."""
    anomalies = []
    if len(concat) < 4:
        return None, ['EAP 长度不足 4 字节']
    code, identifier, length = struct.unpack('!BBH', concat[:4])
    if length < 4 or length > len(concat):
        return None, ['EAP Length 字段 %d 无效（实际 %d 字节）'
                      % (length, len(concat))]
    if length < len(concat):
        anomalies.append('EAP Length 之后还有 %d 字节被忽略'
                         % (len(concat) - length))
    code_name = {1: 'Request', 2: 'Response', 3: 'Success', 4: 'Failure'}.get(
        code, str(code))
    if code in (EAP_SUCCESS, EAP_FAILURE):
        return _ParsedEap(code, identifier, None, None, None, 4, 0,
                          'EAP %s id=%d' % (code_name, identifier)), anomalies
    if length < 5:
        return None, ['EAP %s 缺少 Type 字段' % code_name]
    eap_type = concat[4]
    if eap_type != EAP_TYPE_TLS:
        return _ParsedEap(code, identifier, eap_type, None, None, 5, 0,
                          'EAP %s id=%d type=%d'
                          % (code_name, identifier, eap_type)), anomalies
    if length < 6:
        return None, ['EAP-TLS 缺少 Flags 字段']
    flags = concat[5]
    offset = 6
    tls_length = None
    if flags & FLAG_LENGTH_INCLUDED:
        if length < 10:
            return None, ['EAP-TLS 设置了 L 标志但缺少 TLS Message Length']
        tls_length = struct.unpack('!I', concat[6:10])[0]
        offset = 10
    flag_names = ''.join([
        'L' if flags & FLAG_LENGTH_INCLUDED else '',
        'M' if flags & FLAG_MORE_FRAGMENTS else '',
        'S' if flags & FLAG_START else '']) or '-'
    summary = 'EAP %s/TLS id=%d flags=%s 数据=%d字节' % (
        code_name, identifier, flag_names, length - offset)
    if tls_length is not None:
        summary += ' 声明总长=%d' % tls_length
    return _ParsedEap(code, identifier, eap_type, flags, tls_length,
                      offset, length - offset, summary), anomalies
