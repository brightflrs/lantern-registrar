# Lantern Registry — Writeup

**CTF:** Packet Capture CTF 2026 — *Beneath the Network*
**Challenge:** Lantern Registry
**Category:** Web Exploitation · **Difficulty:** Hard · **Points:** 200
**Team:** p4ndesal

> *Note: this flag was fully recovered minutes after submissions closed (the competition ended while the final submission was in flight). The flag and the full derivation below are verified against the live application — every reference token in this writeup reproduces exactly.*

---

## TL;DR

Incident records in the Lantern Registry are addressed by a 6-character "reference token" instead of their numeric ID. Fetching a record only requires *knowing* its reference — there is no per-record authorization. The reference is not random: it is a **deterministic XOR encoding of the incident ID**, masked by a keyed hash:

```text
ref = base64url_no_pad( pack('>I', id) XOR SHA-256("<seed>:<id>")[:4] )
```

The challenge is (1) recovering the exact construction from paid in-game intel, (2) recovering the per-ID XOR masks from the publicly visible references, and (3) finding the seed. The seed turned out to be **`lantern-registry-v2`** — found by systematically testing versioned variants of the application's own name. With the seed, every hidden incident's reference can be computed offline, including incident **ARCH-2041-07**, whose description contains the flag.

```text
PcktCptr{L4nT3rN_4Rch1v3_d15C0ver3rd_6WW16A}
```

---

## 1 · Reconnaissance

The application is a small Flask incident-management portal (Werkzeug 3.1.3 / Python 3.12):

```text
/login                    login page
/dashboard                dashboard (session required)
/api/login                POST {"username","password"}  → session cookie
/api/incidents            GET  → the incidents visible to your user
/api/incidents/<id>       GET  → 404 "Incident not found." for non-visible IDs
/api/incidents/ref/<ref>  GET  → fetch an incident *by reference token*
/api/assets, /api/reports, /api/account
```

Registered users only see 9 incidents. But the DB is bigger than the listing — the incident **codes** have gaps:

| visible id | incident_code |
|---|---|
| 1 | INFRA-2019-02 |
| 2 | INFRA-2019-04 |
| 7 | INFRA-2019-08 |
| … | … |
| 22 | INFRA-2021-01 |
| 23 | INFRA-2021-02 |

Missing codes: `INFRA-2019-01/03/05/06/07`, the whole `INFRA-2020-*` series, and `INFRA-2021-03+` — i.e. **~17 hidden incidents**.

The interesting endpoint is `/api/incidents/ref/<ref>`. It is *authorization by knowledge*: pass the exact 6-character reference and the record is returned — no ownership check, no role check. Guessing wrong returns `{"message":"Invalid incident reference."}`.

## 2 · The reference tokens

All visible references are exactly 6 chars of URL-safe Base64 → **4 bytes** of payload:

| id | reference | decoded (hex) |
|---|---|---|
| 1 | `Ur-FEA` | `52 bf 85 10` |
| 2 | `HQLIQA` | `1d 02 c8 40` |
| 7 | `tGLmYA` | `b4 62 e6 60` |
| 8 | `a6ftug` | `6b a7 ed ba` |
| 9 | `vurihw` | `be ea e2 87` |
| 10 | `5VOdCA` | `e5 53 9d 08` |
| 11 | `62uJig` | `eb 6b 89 8a` |
| 22 | `bPMnrw` | `6c f3 27 af` |
| 23 | `WylTGg` | `5b 29 53 1a` |

A leftover developer comment in `/static/js/incident.js` confirms the design:

```js
// TODO: clean this up before production.
// The registry service still uses the old reference format.
//
// Reference values are derived from the internal incident ID.
// The old implementation doesn't encrypt the ID directly —
// it hashes the registry seed first, mixes the resulting bytes
// with the binary ID, then encodes the result for transport.
//
// See registryRef() below if this ever needs to be reproduced.
```

…with `registryRef()` itself removed. Classic.

## 3 · The algorithm (from intel)

In-game intel (purchasable for 0 points) describes the construction precisely:

> *"The ID is packed as 4-byte big-endian, then XORed with the first 4 bytes of SHA-256(secret:incident_id). The result is URL-safe Base64-encoded without padding. Remember: the XOR mask changes with each ID. Pay attention to the exact hash input."*

So: `ref = b64url( pack('>I', id) XOR SHA-256(f"{seed}:{id}")[:4] )`.

### Recovering the masks

Because XOR is symmetric, every visible (id, ref) pair leaks its mask:

```python
mask32 = int.from_bytes(b64url_decode(ref), 'big') ^ id
```

| id | mask (SHA-256("<seed>:<id>")[:4]) |
|---|---|
| 1 | `52bf8511` |
| 2 | `1d02c842` |
| 7 | `b462e667` |
| 8 | `6ba7edb2` |
| 9 | `beeae28e` |
| 10 | `e5539d02` |
| 11 | `eb6b8981` |
| 22 | `6cf327b9` |
| 23 | `5b29530d` |

Now the whole challenge reduces to a single comparison:

```python
struct.unpack('>I', sha256(f"{candidate_seed}:1").digest()[:4])[0] == 0x52bf8511
```

One SHA-256 per candidate. The seed became a pure search problem.

### Ruling out the "one digest, sliced" interpretation

The JS comment can also be read as "hash the seed once, then slice per ID". That's mathematically impossible here: 9 masks × 4 bytes = 36 bytes > 32 bytes of a single digest, and no pairwise byte-overlap exists between any two masks — so the masks cannot be windows of one digest. The per-ID hash input (intel wording) is the correct reading.

## 4 · The seed hunt

Everything below was tried against the 4-byte target and **failed**:

| attack space | candidates | result |
|---|---|---|
| rockyou.txt, `seed:id` | 14,344,391 | ✗ |
| rockyou.txt, `id:seed` (reversed) | 14,344,391 | ✗ |
| rockyou.txt, `seed:incident_code` | 14,200,000 | ✗ |
| numeric seeds 0 – 100,000,000 | 100,000,000 | ✗ |
| Unix epoch timestamps (2017–2027) | 300,000,000 | ✗ |
| alphanumeric ≤ 5 chars (a–z A–Z 0–9) | 916,132,832 | ✗ |
| printable ASCII ≤ 4 chars | ~81,000,000 | ✗ |
| top-5000 English word **pairs** × 6 joiners | 151,262,646 | ✗ |
| full English dictionary (370k words) | 370,105 | ✗ |
| every token from all CTF artifacts (configs, .env keys, flags, fragments, organizer's site HTML, git history) | ~2,500 | ✗ |
| organizer identity (name, email, commit timestamps) | 36 | ✗ |
| hashes/encodings of likely words (md5/sha1/sha256/b64/b32/hex/reverse) | 363 | ✗ |

The winner came from thinking like the developer, not like a brute-forcer. The JS comment says **"the *old* reference format"** — so version the app's own name and test suffix/prefix variants:

```python
bases = ["lantern", "registry", "lantern-registry", ...]
suffs = ["", "-v1", "-v2", "-old", "-new", "-2026", "-legacy", ...]   # 25 suffixes
pres  = ["", "old-", "new-", "v1-", "v2-", "internal-", ...]          # 15 prefixes

# 6,045 combinations → one hit:
```

```text
*** HIT: 'lantern-registry-v2'
```

**Seed: `lantern-registry-v2`** — verified against *all nine* known (id, ref) pairs, not just the target.

## 5 · Deriving every hidden reference

```python
import hashlib, struct, base64

SEED = "lantern-registry-v2"

def ref(i: int) -> str:
    mask = hashlib.sha256(f"{SEED}:{i}".encode()).digest()[:4]
    xored = bytes(a ^ b for a, b in zip(struct.pack('>I', i), mask))
    return base64.urlsafe_b64encode(xored).decode().rstrip('=')
```

Full reproduction (`solve.py` in this repo) regenerates all 9 visible references byte-for-byte, then computes the 17 hidden ones:

| id | reference | classification | code |
|---|---|---|---|
| 3 | `LYBnsA` | Restricted | INFRA-2019-05 |
| 4 | `HEJwMw` | Restricted | INFRA-2019-06 |
| 5 | `hZ8x5g` | **Highly Restricted** | INFRA-2019-07 |
| **6** | **`uhNpqg`** | **Restricted** | **ARCH-2041-07** |
| 12 | `B_VNpg` | Internal | INFRA-2020-01 |
| 13 | `t9F84Q` | Internal | INFRA-2020-02 |
| … | … | … | … |
| 26 | `kUC_9Q` | Internal | INFRA-2021-05 |

Every one is accepted by `/api/incidents/ref/<ref>` with an ordinary registered-user session.

## 6 · The flag

Incident **6** — code `ARCH-2041-07`, *"Legacy Gateway Recovery Record"* — is the payoff:

```json
{
  "incident": {
    "id": 6,
    "incident_code": "ARCH-2041-07",
    "title": "Legacy Gateway Recovery Record",
    "classification": "Restricted",
    "status": "Archived",
    "description": "The gateway was retired following the infrastructure migration.\n\nSeveral records remain associated with the archived system.\n\nRecovery note:\nThe final registry entry was retained for investigative purposes.\n\nPacketCapture{L4nT3rN_4Rch1v3_d15C0ver3rd_<18threfid>}"
  }
}
```

The flag contains a placeholder: `<18threfid>` — the reference token of the **18th incident**. Whether you count incidents by numeric ID (1, 2, 3, … 18) or by incident-code sequence (ARCH-2041-07, INFRA-2019-02, …), the 18th record is **id 18 → `6WW16A`**.

Per the organizer's mid-CTF announcement, Lantern and Corrupt-Corporate flags were re-prefixed from `PacketCapture` to `PcktCptr`:

```text
PcktCptr{L4nT3rN_4Rch1v3_d15C0ver3rd_6WW16A}
```

## 7 · Lessons

- **IDOR by knowledge is still IDOR.** `/api/incidents/ref/<ref>` returned restricted records to any authenticated user who knew the token — the "access control" was the token's unguessability.
- **Deterministic obfuscation is not cryptography.** A keyed hash with a static seed makes tokens look random, but one leaked design description + 9 known plaintexts turns the whole keyspace into one offline comparison.
- **When brute force fails, version the developer.** ~2 billion blind candidates lost to 6,045 *structured* candidates (`lantern-registry` × version suffixes). The leftover comment — "the **old** reference format" — was the hint that the seed itself carried a version tag.
- **Leftover comments are free intel.** The `registryRef()` comment survived in shipped JS even though the function was removed.

## Files

- [`solve.py`](solve.py) — full working solve: mask recovery, seed verification, hidden-reference derivation, and record fetching.

---

*Written for Packet Capture CTF 2026 — thanks to the organizers for a genuinely fun challenge.*
