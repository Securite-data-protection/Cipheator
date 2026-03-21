#!/usr/bin/env python3
import argparse
import os
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from protocol_client import ProtocolClient


def worker(client, username, password, cipher, hash_alg, key_storage, size_bytes, idx):
    data = os.urandom(size_bytes)
    resp, enc = client.encrypt(username, password, data, cipher, hash_alg,
                               key_storage=key_storage,
                               file_name=f"load_{idx}.bin")
    if resp.get("status") != "ok":
        return False, f"encrypt failed: {resp.get('message')}"

    file_id = resp.get("file_id", "")
    key_id = resp.get("key_id", "")

    # Decrypt using server-stored key (key_id)
    resp2, plain = client.decrypt(username, password, enc, cipher, hash_alg,
                                  file_id=file_id, key_id=key_id)
    if resp2.get("status") != "ok":
        return False, f"decrypt failed: {resp2.get('message')}"

    # Simulated copy: memory-only copy to emulate client-side transfer
    _ = plain[:]
    return True, "ok"


def main():
    parser = argparse.ArgumentParser(description="K-2 load test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7443)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--cipher", default="aes-256-gcm")
    parser.add_argument("--hash", dest="hash_alg", default="sha256")
    parser.add_argument("--key-storage", default="server")
    parser.add_argument("--files", type=int, default=1000)
    parser.add_argument("--min-kb", type=int, default=10)
    parser.add_argument("--max-mb", type=int, default=10)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--ca")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    client = ProtocolClient(args.host, args.port, cafile=args.ca, verify=not args.insecure)
    total = args.files
    min_bytes = args.min_kb * 1024
    max_bytes = args.max_mb * 1024 * 1024

    sizes = [random.randint(min_bytes, max_bytes) for _ in range(total)]

    start = time.perf_counter()
    ok_count = 0
    errors = 0

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(worker, client, args.user, args.password,
                             args.cipher, args.hash_alg, args.key_storage,
                             sizes[i], i)
                   for i in range(total)]
        for fut in as_completed(futures):
            ok, msg = fut.result()
            if ok:
                ok_count += 1
            else:
                errors += 1

    elapsed = time.perf_counter() - start
    print("K-2 Load Test")
    print(f"total={total} ok={ok_count} errors={errors}")
    print(f"elapsed_sec={elapsed:.2f}")


if __name__ == "__main__":
    main()
