#!/usr/bin/env python3
import argparse
import os
import time

from protocol_client import ProtocolClient


def parse_sizes(arg):
    out = []
    for part in arg.split(","):
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    return out


def main():
    parser = argparse.ArgumentParser(description="K-1 performance benchmark")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7443)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--cipher", default="aes-256-gcm")
    parser.add_argument("--hash", dest="hash_alg", default="sha256")
    parser.add_argument("--key-storage", default="server")
    parser.add_argument("--sizes-mb", default="1,10,100,250")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--ca")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    sizes = parse_sizes(args.sizes_mb)
    client = ProtocolClient(args.host, args.port, cafile=args.ca, verify=not args.insecure)

    print("K-1 Performance Test")
    print(f"cipher={args.cipher} hash={args.hash_alg} repeats={args.repeats}")

    for mb in sizes:
        size_bytes = mb * 1024 * 1024
        timings = []
        for i in range(args.repeats):
            data = os.urandom(size_bytes)
            start = time.perf_counter()
            resp, _ = client.encrypt(args.user, args.password, data, args.cipher, args.hash_alg,
                                    key_storage=args.key_storage,
                                    file_name=f"bench_{mb}mb.bin")
            elapsed = time.perf_counter() - start
            if resp.get("status") != "ok":
                raise RuntimeError(f"Encrypt failed: {resp.get('message')}")
            timings.append(elapsed)
        avg = sum(timings) / len(timings)
        print(f"{mb}MB avg={avg:.4f}s samples={[round(t,4) for t in timings]}")


if __name__ == "__main__":
    main()
