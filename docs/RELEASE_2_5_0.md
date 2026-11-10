<!-- Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com> -->
<!-- SPDX-License-Identifier: MIT -->

# statusbar 2.5.0

Released 2026-11-10. What the release contains, what changed on the wire
and in the public APIs, how it was built, verified and deployed, and where
the per-repository detail is.

2.5.0 is the IEEE 1722 security release. The ECC1 encrypted control format
is corrected to IEEE Std 1722-2025 and IEEE 1363a-2004 as written, and the
stack implements the November 2026 proposal to the IEEE 1722 working group
("IEEE Std 1722-2025 security clauses: corrections and new variants") as its
proof of concept: RFC 9180 HPKE encryption variants ECC2 (P-256) and ECC3
(X25519), an Ed25519 signature variant for ESCF, 16-bit length fields, and
a symmetric 100 ms PTP window on both formats' timestamps. Beside it: three
IEEE 1722.1-2021 conformance fixes in the ATDECC code and two timing fixes
from the fork review.

## The tags

| Repository       | Tag(s)                        | Commit    | Previous |
|------------------|-------------------------------|-----------|----------|
| core             | `2.5.0`                       | `71a803c` | `ae2b4f3` (2.4.1) |
| crypto           | `2.5.0`                       | `2f15657` | `f627c13` (2.4.1) |
| audio            | `2.5.0`                       | `a2cf15c` | `0a1ebf7` (2.4.1) |
| avb              | `2.5.0`, `wireshark-v2.5.0`   | `d814ac9` | `2664ebd` (2.4.1) |
| atdecc-control   | `2.5.0`                       | `4ad80a7` | `d744135` (2.4.1) |
| umbrella         | `2.5.0`                       | `544126c` | `1d66cd1` (2.4.1) |

audio and atdecc-control carry only the version bump. The mains and the
tags are on the staging remote and on all three public mirrors (opensource,
Codeberg, GitHub), verified ref-for-ref after the push.

## What changed

### crypto (2.4.1 to 2.5.0, 5 commits including the version bump)

- **ECIES key order (IEEE 1363a-2004 11.3.2 step 10a).** The KDF output
  is K1 ‖ K2 with K1, the leftmost 256 bits, the AES key and K2 the MAC
  key. 2.4.x had them swapped, so 2.4.x ECC1 payloads do not decrypt on
  2.5.0 and vice versa. Known-answer tests pin the corrected order.
- **AES-GCM.** AES-128-GCM and AES-256-GCM (NIST SP 800-38D, RFC 5116)
  with the NIST and RFC vectors.
- **HPKE (RFC 9180).** DHKEM(P-256, HKDF-SHA256) and
  DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM and AES-256-GCM, all
  four modes, the exporter, and the sixteen CFRG test vectors for these two
  KEMs. The API is generic over the KEM: `HpkeKem`, `HpkeContext::kem`,
  `HpkeSenderSetup<Nenc>`, and the setup functions overloaded on the key
  type. The Python mirror (`python/crypto/statusbar_crypto.py`) follows.

### core (2.4.1 to 2.5.0, 2 commits including the version bump)

- **`LaunchOrder` on a failed clock read.** `tai_now_ns()` and a PHC read
  answer 0 when the read fails; `next()` read that as the clock stepping
  back an epoch and handed out the stale time, ahead of the frames already
  queued. A 0 `now` now leaves an untimed frame untimed, holds a timed one
  at the last time handed out, and counts nothing.

### avb (2.4.1 to 2.5.0, 8 commits including the version bump)

- **EECF ECC1 payload (IEEE 1722-2025 17.3.2).** The encrypted_payload is
  V ‖ T ‖ C as the figure draws it (ephemeral key, tag, ciphertext), with a
  codec (`eecf_ecc1_*`), tool commands and the Python mirror; the dissector
  splits it. With the crypto key-order fix this is a wire change from
  2.4.x.
- **The amendment proof of concept.** `enc` values ECC2 = 1 (HPKE P-256)
  and ECC3 = 2 (HPKE X25519): base mode, AES-256-GCM, info
  `"IEEE 1722 EECF ECC2"` / `"IEEE 1722 EECF ECC3"`, the 12-octet header as
  AAD, payload enc ‖ C ‖ T, EncapMTU = MTU − 36 − Npk. `sig` value
  ED25519 = 1 for ESCF (RFC 8032 5.1, no prehash or context, over
  key_id ‖ signing_timestamp ‖ encapsulated_avtpdu), and the ESCF header
  as the amendment draws it: 84 octets, a single 64-octet `signature_value`
  (ECSSA keeps c then d). Both formats' length fields are the full 16 bits
  of Figures 109 and 110; the old reserved(5) ‖ length(11) model was wrong.
  A Listener discards an ESCF signing_timestamp or a decrypted EECF
  encryption_timestamp more than 100 ms from its own PTP time in either
  direction; both parties share PTP time. New `avtp_crypto/avtp_escf_frame`
  (signed message, ECSSA and Ed25519 sign/verify, frames), `eecf_ecc2_*` /
  `eecf_ecc3_*`, tool commands, the Python mirror cross-checked against the
  tool, the dissector (ESCF layout, ECC1/2/3 payload split) and five new
  golden-capture frames. `docs/IEEE_1722_CRYPTO_AMENDMENT.md` maps every
  item of the proposal to the code and carries the test vectors.
- **STREAM_OUTPUT counters on the 2021 bits (IEEE 1722.1-2021 Table
  7-158).** The counter table lacked STREAM_INTERRUPTED, so every name from
  bit 2 on was one bit early and the entity emitted FRAMES_TX on bit 6,
  which a 2021 controller reads as TIMESTAMP_NOT_VALID. Tool, supervise
  constant and entity now use bit 7; the entity-specific labels are in
  the standard's order.
- **STOP_STREAMING shows as STREAMING_WAIT (Table 7-145).** A stopped
  STREAM_OUTPUT reports the flag in GET_STREAM_INFO, and the kit pushes an
  unsolicited GET_STREAM_INFO on each STOP/START beside the command echo.
- **MSRP state-change hooks are told the event's time.**
  `on_listener_state_change` and `on_talker_state_change` take the
  `TimePoint` of the receive or tick they fire from.

## Downstream: what a tree built on 2.4.x must change

- **Wire.** ECC1 payloads are not interoperable with 2.4.x (key order and
  V ‖ T ‖ C layout). ESCF frames are not interoperable with 2.4.x (84-octet
  header, `signature_value`). Both now follow the published standard, so a
  conformant third-party implementation interoperates where 2.4.x did not.
  EECF `encrypted_payload_length` and ESCF `encapsulated_avtpdu_length`
  are 16-bit fields.
- `EscfPdu`: `signature_value()` / `set_signature_value()` replace the c/d
  accessors; `escf_get_encapsulated_avtpdu()` replaces
  `escf_get_signed_payload()`; `EscfSigMode::ed25519` and
  `EecfEncMode::ecc2` / `ecc3` are new values.
- `crypto/hpke`: `hpke_kem_id` is gone; `HpkeSenderSetup` is
  `HpkeSenderSetup<Nenc>` (`HpkeP256SenderSetup`, `HpkeX25519SenderSetup`);
  setup functions are overloaded on `P256PublicKey` / `X25519PublicKey`.
- `MsrpCallbacks::on_talker_state_change` and `on_listener_state_change`
  gained a trailing `TimePoint now`.
- `avb_entity::fill_talker_stream_info` takes the talker's stopped latch;
  `STREAM_OUTPUT_FRAMES_TX_BIT` is 7. A controller polling a 2.4.x entity
  still finds its FRAMES_TX on bit 6.
- `LaunchOrder::next(wanted, 0)` no longer returns `wanted`; see
  `net_launch_order.hpp`.

## Build, test and deploy

- Each repository landed through the CI branch flow (`ci/<name>` built and
  cherry-picked onto main by the cron, result tag per branch); the version
  bumps were the last four branches. Suites at the tags: core 84, crypto
  44, audio 19, avb 169, atdecc-control 35 C++ tests, plus the crypto and avb Python suites (157 frame
  tests against the C++ tool) and the tshark golden capture (162 frames).
- Packages: suite `2.5.0-20261110084919`, cross-built in podman from the
  tagged trees with the umbrella's `container-build-cross.sh` and
  atdecc-control's, one `STATUSBAR_DEB_REVISION` for all six runtime
  packages (core, crypto, audio, avb, avb-wireshark, atdecc-control).
- Fleet: all five Raspberry Pi 5 nodes (jdk01a, jdk01b, jdk01c, jdk01d,
  jdk01f) upgraded with `dpkg -i`:
  all eleven packages on each node at `2.5.0-20261110084919`, dpkg exit 0
  everywhere. The tone generators on jdk01f and jdk01c were restarted by the
  package postinst and report healthy; on jdk01c the device proxies and the
  widget bridge, now systemd units, were restarted and came back healthy.

## Where the detail is

- `avb/docs/IEEE_1722_CRYPTO_AMENDMENT.md`: the proposal item by item,
  the 17.4 and 16.4 text, the keys and test vectors, and the code map.
- `crypto/docs/HPKE_MODULE.md`, `AES_GCM_MODULE.md`, `ECIES_MODULE.md`: the
  primitives and their vectors.
- `avb/docs/TOOLS.md`: the `statusbar-avtp-crypto-tool` commands for
  interoperability testing (`eecf_ecc1_*`, `eecf_ecc2_*`, `eecf_ecc3_*`,
  `escf_sign` / `escf_verify`, `hpke_x25519_keypair`).
- `avb/wireshark/README.md`: the dissector's ESCF and EECF coverage and the
  golden capture.
- `RELEASE_2_4_0.md` (this folder): the previous release.
