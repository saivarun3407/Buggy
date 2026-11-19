"""Scope-filtering DNS proxy for the egress guard (standard library only).

The sandbox's resolver points here. A query is forwarded upstream only when
the active policy allows its name; every other query is answered
``REFUSED`` and logged. Addresses in allowed answers are handed to the
firewall so the sandbox can connect to exactly what it was allowed to
resolve, for the record's TTL.

Only the pieces of RFC 1035 needed for that are implemented: reading the
question, and walking the answer section for A records.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass

log = logging.getLogger("buggy.egress_guard.dns")

RCODE_SERVFAIL = 2
RCODE_REFUSED = 5
TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1
_MAX_UDP = 4096
_MAX_POINTER_HOPS = 32


class DNSParseError(ValueError):
    """The packet is not a DNS message this proxy can read."""


@dataclass(frozen=True, slots=True)
class Question:
    txid: int
    name: str
    qtype: int
    qclass: int
    end: int  # offset just past the question section


@dataclass(frozen=True, slots=True)
class Address:
    name: str
    address: str
    ttl: int


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Read a possibly-compressed name; return ``(name, offset_after)``."""
    labels: list[str] = []
    cursor = offset
    after: int | None = None
    hops = 0
    while True:
        if cursor >= len(packet):
            raise DNSParseError("name runs past end of packet")
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise DNSParseError("truncated compression pointer")
            if after is None:
                after = cursor + 2
            cursor = ((length & 0x3F) << 8) | packet[cursor + 1]
            hops += 1
            if hops > _MAX_POINTER_HOPS:
                raise DNSParseError("compression pointer loop")
            continue
        if length & 0xC0:
            raise DNSParseError("unsupported label type")
        cursor += 1
        if length == 0:
            break
        if cursor + length > len(packet):
            raise DNSParseError("label runs past end of packet")
        labels.append(packet[cursor : cursor + length].decode("ascii", "replace"))
        cursor += length
        if len(labels) > 127:
            raise DNSParseError("too many labels")
    return ".".join(labels), (after if after is not None else cursor)


def parse_question(packet: bytes) -> Question:
    """Parse the header and first question of a query."""
    if len(packet) < 12:
        raise DNSParseError("short header")
    txid, flags, qdcount = struct.unpack("!HHH", packet[:6])
    if flags & 0x8000:
        raise DNSParseError("not a query")
    if qdcount != 1:
        raise DNSParseError("expected exactly one question")
    name, offset = _read_name(packet, 12)
    if offset + 4 > len(packet):
        raise DNSParseError("truncated question")
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    return Question(txid=txid, name=name, qtype=qtype, qclass=qclass, end=offset + 4)


def build_error(query: bytes, rcode: int) -> bytes:
    """A response to ``query`` carrying ``rcode`` and no records."""
    try:
        question = parse_question(query)
        body = query[12 : question.end]
        qdcount = 1
    except DNSParseError:
        body = b""
        qdcount = 0
    txid = struct.unpack("!H", query[:2])[0] if len(query) >= 2 else 0
    opcode_rd = (struct.unpack("!H", query[2:4])[0] & 0x7900) if len(query) >= 4 else 0
    flags = 0x8000 | opcode_rd | 0x0080 | (rcode & 0x000F)
    return struct.pack("!HHHHHH", txid, flags, qdcount, 0, 0, 0) + body


def extract_addresses(response: bytes) -> list[Address]:
    """IPv4 addresses from the answer section of ``response``."""
    if len(response) < 12:
        raise DNSParseError("short header")
    _txid, _flags, qdcount, ancount = struct.unpack("!HHHH", response[:8])
    offset = 12
    for _ in range(qdcount):
        _name, offset = _read_name(response, offset)
        offset += 4
    found: list[Address] = []
    for _ in range(ancount):
        name, offset = _read_name(response, offset)
        if offset + 10 > len(response):
            raise DNSParseError("truncated record header")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", response[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(response):
            raise DNSParseError("truncated record data")
        if rtype == TYPE_A and rclass == CLASS_IN and rdlength == 4:
            found.append(
                Address(
                    name=name.lower(),
                    address=socket.inet_ntoa(response[offset : offset + 4]),
                    ttl=int(ttl),
                )
            )
        offset += rdlength
    return found


def read_resolvers(path: str = "/etc/resolv.conf") -> list[str]:
    resolvers: list[str] = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    resolvers.append(parts[1])
    except OSError as exc:
        log.warning("dns: cannot read %s: %s", path, exc)
    return resolvers


def forward_udp(query: bytes, upstream: str, *, timeout: float = 3.0) -> bytes:
    family = socket.AF_INET6 if ":" in upstream else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (upstream, 53))
        while True:
            data, _addr = sock.recvfrom(_MAX_UDP)
            if len(data) >= 2 and data[:2] == query[:2]:
                return data


def forward_tcp(query: bytes, upstream: str, *, timeout: float = 5.0) -> bytes:
    with socket.create_connection((upstream, 53), timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(query)) + query)
        header = _recv_exact(sock, 2)
        (length,) = struct.unpack("!H", header)
        return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise OSError("upstream closed the connection")
        chunks.extend(chunk)
    return bytes(chunks)


# decide(name) -> (allow, reason); on_refused(name, qtype, reason, client);
# on_answer(name, [Address]) is called only for allowed answers.
Decide = Callable[[str], tuple[bool, str]]
OnRefused = Callable[[str, int, str, str], None]
OnAnswer = Callable[[str, list[Address]], None]
Forward = Callable[[bytes, str], bytes]


class Resolver:
    """Decision + forwarding logic shared by the UDP and TCP listeners."""

    def __init__(
        self,
        *,
        decide: Decide,
        on_refused: OnRefused,
        on_answer: OnAnswer,
        upstreams: list[str],
        udp_forward: Forward | None = None,
        tcp_forward: Forward | None = None,
    ) -> None:
        self._decide = decide
        self._on_refused = on_refused
        self._on_answer = on_answer
        self._upstreams = upstreams
        self._udp = udp_forward or forward_udp
        self._tcp = tcp_forward or forward_tcp

    def handle(self, query: bytes, client: str, *, tcp: bool) -> bytes:
        try:
            question = parse_question(query)
        except DNSParseError:
            return build_error(query, RCODE_REFUSED)
        allow, reason = self._decide(question.name)
        if not allow:
            self._on_refused(question.name, question.qtype, reason, client)
            return build_error(query, RCODE_REFUSED)
        response = self._forward(query, tcp=tcp)
        if response is None:
            return build_error(query, RCODE_SERVFAIL)
        try:
            addresses = extract_addresses(response)
        except DNSParseError:
            # An answer we cannot read is an answer we cannot vet.
            return build_error(query, RCODE_SERVFAIL)
        if addresses:
            self._on_answer(question.name, addresses)
        return response

    def _forward(self, query: bytes, *, tcp: bool) -> bytes | None:
        for upstream in self._upstreams:
            try:
                if tcp:
                    return self._tcp(query, upstream)
                response = self._udp(query, upstream)
                if len(response) >= 4 and response[2] & 0x02:  # TC: retry over TCP
                    return self._tcp(query, upstream)
                return response
            except OSError as exc:
                log.warning("dns: upstream %s failed: %s", upstream, exc)
        return None


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        resolver: Resolver = self.server.resolver  # type: ignore[attr-defined]
        reply = resolver.handle(data, self.client_address[0], tcp=False)
        if len(reply) > _MAX_UDP:
            # Too large for UDP: answer empty with TC set so the client retries over TCP.
            empty = build_error(data, 0)
            reply = empty[:2] + bytes([empty[2] | 0x02]) + empty[3:]
        sock.sendto(reply, self.client_address)


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(10)
        resolver: Resolver = self.server.resolver  # type: ignore[attr-defined]
        try:
            while True:
                header = _recv_exact(self.request, 2)
                (length,) = struct.unpack("!H", header)
                query = _recv_exact(self.request, length)
                reply = resolver.handle(query, self.client_address[0], tcp=True)
                self.request.sendall(struct.pack("!H", len(reply)) + reply)
        except OSError:
            return


class _ThreadedUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class _ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(resolver: Resolver, bind: str, port: int = 53) -> list[socketserver.BaseServer]:
    """Start UDP and TCP listeners on ``bind``; return the running servers."""
    udp = _ThreadedUDP((bind, port), _UDPHandler)
    tcp = _ThreadedTCP((bind, port), _TCPHandler)
    servers: list[socketserver.BaseServer] = [udp, tcp]
    for server in servers:
        server.resolver = resolver  # type: ignore[attr-defined]
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return servers


__all__ = [
    "Address",
    "DNSParseError",
    "Question",
    "Resolver",
    "build_error",
    "extract_addresses",
    "parse_question",
    "read_resolvers",
    "serve",
]
