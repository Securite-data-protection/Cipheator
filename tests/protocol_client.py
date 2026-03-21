#!/usr/bin/env python3
import argparse
import os
import socket
import ssl
import sys
import time
import hashlib

HEADER_TERM = b"\n\n"


def _client_id():
    host = os.environ.get("HOSTNAME") or socket.gethostname()
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE") or ""
    seed = f"{host}|{user}|{home}".encode("utf-8")
    return hashlib.sha256(seed).hexdigest()


def _client_host():
    return os.environ.get("HOSTNAME") or socket.gethostname() or "unknown-host"


def _serialize_header(fields):
    lines = []
    for k, v in fields.items():
        lines.append(f"{k}: {v}")
    return ("\n".join(lines) + "\n\n").encode("utf-8")


def _read_until(sock, marker, limit=65536):
    buf = bytearray()
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            raise RuntimeError("Header too large")
    return bytes(buf)


def _parse_header(raw):
    header_part = raw.split(HEADER_TERM, 1)[0]
    text = header_part.decode("utf-8", errors="replace")
    fields = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        fields[k.strip()] = v.strip()
    return fields


def _recv_exact(sock, size):
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise RuntimeError("Connection closed")
        buf += chunk
    return bytes(buf)


class ProtocolClient:
    def __init__(self, host, port, cafile=None, verify=True, timeout=30):
        self.host = host
        self.port = port
        self.cafile = cafile
        self.verify = verify
        self.timeout = timeout

    def _connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        ctx = ssl.create_default_context(cafile=self.cafile) if self.verify else ssl._create_unverified_context()
        if not self.verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(raw, server_hostname=self.host)
        return tls

    def send_request(self, header_fields, payload=b""):
        with self._connect() as s:
            s.sendall(_serialize_header(header_fields))
            if payload:
                s.sendall(payload)
            raw = _read_until(s, HEADER_TERM, limit=65536)
            if HEADER_TERM not in raw:
                raise RuntimeError("Invalid response header")
            header = _parse_header(raw)
            leftover = raw.split(HEADER_TERM, 1)[1]

            size = 0
            if "enc_size" in header:
                size = int(header["enc_size"])
            elif "plain_size" in header:
                size = int(header["plain_size"])

            body = b""
            if size > 0:
                if leftover:
                    body = leftover
                if len(body) < size:
                    body += _recv_exact(s, size - len(body))
                body = body[:size]
            return header, body

    def encrypt(self, username, password, data, cipher, hash_alg, key_storage="server", file_name="input.bin"):
        header = {
            "op": "encrypt",
            "username": username,
            "password": password,
            "client_id": _client_id(),
            "client_host": _client_host(),
            "cipher": cipher,
            "hash": hash_alg,
            "key_storage": key_storage,
            "file_name": file_name,
            "file_size": str(len(data)),
        }
        resp, body = self.send_request(header, payload=data)
        return resp, body

    def decrypt(self, username, password, ciphertext, cipher, hash_alg, file_id="", key_id="", key_b64="", iv_b64="", tag_b64=""):
        header = {
            "op": "decrypt",
            "username": username,
            "password": password,
            "client_id": _client_id(),
            "client_host": _client_host(),
            "cipher": cipher,
            "hash": hash_alg,
            "file_size": str(len(ciphertext)),
        }
        if file_id:
            header["file_id"] = file_id
        if key_id:
            header["key_id"] = key_id
        if key_b64:
            header["key"] = key_b64
        if iv_b64:
            header["iv"] = iv_b64
        if tag_b64:
            header["tag"] = tag_b64
        resp, body = self.send_request(header, payload=ciphertext)
        return resp, body


def main():
    parser = argparse.ArgumentParser(description="Cipheator protocol client (encrypt/decrypt)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7443)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--cipher", default="aes-256-gcm")
    parser.add_argument("--hash", dest="hash_alg", default="sha256")
    parser.add_argument("--ca")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--mode", choices=["encrypt"], default="encrypt")
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    with open(args.file, "rb") as f:
        data = f.read()

    client = ProtocolClient(args.host, args.port, cafile=args.ca, verify=not args.insecure)
    start = time.perf_counter()
    resp, body = client.encrypt(args.user, args.password, data, args.cipher, args.hash_alg)
    elapsed = (time.perf_counter() - start) * 1000.0

    print("status:", resp.get("status"))
    print("message:", resp.get("message", ""))
    print("file_id:", resp.get("file_id", ""))
    print("key_id:", resp.get("key_id", ""))
    print("enc_size:", len(body))
    print("elapsed_ms:", f"{elapsed:.2f}")


if __name__ == "__main__":
    main()
