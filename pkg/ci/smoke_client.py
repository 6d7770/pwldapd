#!/usr/bin/env python3
"""Minimal LDAP smoke test for an installed pwldapd.

Performs an anonymous bind, reads the root DSE and lists the people OU
over a plain TCP connection. Exits non-zero on any unexpected response.
Usage: smoke_client.py HOST PORT BASE_DN
"""
import socket
import sys


def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82, n >> 8, n & 0xff])
    return bytes([tag]) + length + content


def integer(n):
    body = n.to_bytes(8, "big", signed=True).lstrip(b"\0") or b"\0"
    if body[0] & 0x80:
        body = b"\0" + body
    return tlv(0x02, body)


def enum(n):
    return tlv(0x0a, bytes([n]))


def string(s):
    return tlv(0x04, s.encode())


def message(mid, op):
    return tlv(0x30, integer(mid) + op)


def bind(mid):
    return message(mid, tlv(0x60, integer(3) + string("") + tlv(0x80, b"")))


def search(mid, base, scope):
    body = (string(base) + enum(scope) + enum(0) + integer(0) + integer(0)
            + tlv(0x01, b"\0") + tlv(0x87, b"objectClass") + tlv(0x30, b""))
    return message(mid, tlv(0x63, body))


def parse_tlv(buf):
    tag, first = buf[0], buf[1]
    i = 2
    if first & 0x80:
        n = first & 0x7f
        length = int.from_bytes(buf[2:2 + n], "big")
        i = 2 + n
    else:
        length = first
    return tag, buf[i:i + length], buf[i + length:]


def read_message(sock):
    head = sock.recv(2)
    if len(head) < 2:
        raise SystemExit("connection closed")
    length, extra = head[1], b""
    if length & 0x80:
        extra = sock.recv(length & 0x7f)
        length = int.from_bytes(extra, "big")
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise SystemExit("connection closed mid-message")
        body += chunk
    _, seq, _ = parse_tlv(head + extra + body)
    _, mid, rest = parse_tlv(seq)
    tag, value, _ = parse_tlv(rest)
    return int.from_bytes(mid, "big", signed=True), tag, value


def result_code(value):
    _, code, _ = parse_tlv(value)
    return code[0]


def read_search(sock):
    entries = []
    while True:
        _, tag, value = read_message(sock)
        if tag == 0x64:
            _, dn, _ = parse_tlv(value)
            entries.append(dn.decode())
        elif tag == 0x65:
            return entries, result_code(value)
        else:
            raise SystemExit(f"unexpected response tag {tag:#x}")


def main():
    host, port, base = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    sock = socket.create_connection((host, port), timeout=10)
    sock.sendall(bind(1))
    mid, tag, value = read_message(sock)
    if (mid, tag, result_code(value)) != (1, 0x61, 0):
        raise SystemExit(f"anonymous bind failed: {mid} {tag:#x}")
    print("bind ok")

    sock.sendall(search(2, "", 0))
    entries, code = read_search(sock)
    if entries != [""] or code != 0:
        raise SystemExit(f"root DSE search failed: {entries} code {code}")
    print("root DSE ok")

    sock.sendall(search(3, f"ou=people,{base}", 1))
    entries, code = read_search(sock)
    if code != 0 or not entries:
        raise SystemExit(f"people search failed: {len(entries)} entries, code {code}")
    print(f"people search ok ({len(entries)} entries)")

    sock.sendall(message(4, tlv(0x42, b"")))
    sock.close()
    print("smoke test passed")


if __name__ == "__main__":
    main()
