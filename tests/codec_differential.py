#!/usr/bin/env python3
"""Differential test: nanom's Snappy / LZ4-block decoders vs pyarrow's compressors.

Compresses a few hundred buffers (random, repetitive, text-like, all sizes from 0 to 256 KiB) with
pyarrow's snappy and lz4_raw codecs and checks codec_check reproduces the original bytes exactly.
usage: codec_differential.py /path/to/codec_check     (exit 77 = skipped: no pyarrow)
"""
import os
import random
import subprocess
import sys
import tempfile

try:
    import pyarrow as pa
except ImportError:
    print("pyarrow not installed: skipping")
    sys.exit(77)


def buffers(rng):
    sizes = [0, 1, 2, 3, 4, 15, 16, 17, 64, 65, 255, 256, 4096, 65535, 65536, 65537, 262144]
    sizes += [rng.randrange(0, 200000) for _ in range(60)]
    for n in sizes:
        yield bytes(rng.getrandbits(8) for _ in range(min(n, 5000))) + bytes(max(0, n - 5000))
        yield (b"parquet nanom " * (n // 14 + 1))[:n]
        alphabet = b"abcd"
        yield bytes(rng.choice(alphabet) for _ in range(min(n, 20000))) * (n // 20000 + 1)
        yield b"".join(rng.getrandbits(32).to_bytes(4, "little") * rng.randrange(1, 9)
                       for _ in range(n // 16))


def main():
    tool = sys.argv[1]
    rng = random.Random(7)
    with tempfile.TemporaryDirectory() as d:
        lines = []
        for i, raw in enumerate(buffers(rng)):
            for codec in ("snappy", "lz4_raw"):
                if codec == "lz4_raw" and not raw:
                    continue  # an empty LZ4 block is not a valid input
                comp = pa.compress(raw, codec=codec, asbytes=True)
                cp, ep = os.path.join(d, f"{i}.{codec}"), os.path.join(d, f"{i}.raw")
                open(cp, "wb").write(comp)
                open(ep, "wb").write(raw)
                lines.append(f"{codec} {cp} {ep}\n")
        man = os.path.join(d, "manifest.txt")
        open(man, "w").writelines(lines)
        return subprocess.run([tool, man]).returncode


if __name__ == "__main__":
    sys.exit(main())
