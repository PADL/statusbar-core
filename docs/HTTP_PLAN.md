# statusbar/http — Embedded HTTP/1.1 + WebSocket Server Plan

Status: IMPLEMENTED — milestones M0–M5 are landed in this repo. M6 is
the first real consumer and lives outside core. Measured on an M-series
Mac (Release): ~210 ns per parsed request head, ~25k req/s sequential
keep-alive on loopback (syscall-bound, client and server sharing one
thread), ~140k req/s pipelined ×8; `statusbar-http-bench --check` gates
regressions in CI-shaped optimized builds, and
`http_alloc_gate_test.cpp` proves the zero-allocation steady state.

## 0. Purpose

An embedded web server for control-surface UIs: small enough to reason
about completely, allocation-free after startup, and event-driven on the
existing `MessageReactor`. The long-term consumer is a web-app server
whose pages render real-time control-point widgets mapped to discovered
IEEE 1722.1 control points — but nothing 1722.1-shaped may appear in
this module. Core serves bytes; the control plane is someone else's
layer (§8).

Hard requirements:

- HTTP/1.1: GET / HEAD / PUT / POST, keep-alive.
- WebSocket (RFC 6455).
- Static files from a manifest loaded at startup (URI → filesystem
  path), not from directory walking.
- **No dynamic memory allocation after startup.** Startup may size and
  allocate everything (connection slots, buffers, manifest tables);
  the steady-state request path may not touch the heap.
- No TLS. Encryption is a front-end terminator's job (nginx/caddy do
  `https:`/`wss:` toward clients and plain `http:`/`ws:` upstream).

Explicitly out of scope, permanently or until a milestone demands it:
HTTP/2 and HTTP/3 (the terminator may speak them client-side),
compression, inbound `Transfer-Encoding: chunked`, multipart parsing,
CGI/proxying, directory listings, TLS.

## 1. Context

### Dependencies (all in-repo)

| module | provides |
| --- | --- |
| `net` | `TcpConnectionPool` + `FdMultiplexer` (fixed-capacity, readiness-driven transport; short-write/`on_writable` backpressure contract), `SocketAddress`, `ServerConfig` |
| `toml` | the manifest file format |
| `buffer` | `FileDescriptor`, span utilities |
| `container` | `SlotTable` where per-request bookkeeping needs it |
| `sm` | connection lifecycle state machine (optional; a plain enum may suffice — decide in M1) |
| `status` | `Status` / `StatusValue` error discipline |

No dependency on `crypto`: the WebSocket handshake needs SHA-1 +
base64, which is a nonce transform, not security — a self-contained
~60-line implementation lives inside this module, commented as
handshake-only (§6.1).

### Proposed layout

```
statusbar/http/
  http_limits.hpp            init-time capacity/limit set
  http_parser.{hpp,cpp}      incremental request parser
  http_router.{hpp,cpp}      manifest table + registered handlers
  http_static.{hpp,cpp}      manifest load, file sources, conditional GET
  http_server.{hpp,cpp}      HttpServer: TcpConnectionHandler impl
  http_ws.{hpp,cpp}          WebSocket handshake + frame codec
  http_sha1.{hpp,cpp}        handshake-only SHA-1 + base64
  http_server_example.cpp    manifest site + echo WS endpoint
  *_test.cpp                 per-unit tests (see milestones)
```

## 2. Architecture

One `HttpServer` implements `net::TcpConnectionHandler` over one
`TcpConnectionPool`; the whole server is a single `Pollable` in the
reactor. Per pool slot there is one `Connection` record — parser state,
fixed rx buffer, fixed tx buffer, mode (http / websocket), timers —
all preallocated from `HttpLimits` at construction.

```
reactor ── TcpConnectionPool ── HttpServer (TcpConnectionHandler)
                                   │ per-slot Connection
                                   │   rx buf → HttpParser ─→ Router
                                   │   tx buf ← ResponseWriter ← handler / static source
                                   │   or: WsConnection (after upgrade)
                                   └ Router: StaticManifest + registered routes
```

Data flow rules:

- **rx**: `on_readable` reads into the slot's rx buffer and feeds the
  parser incrementally; the parser never copies — request line, header
  names/values are `string_view`s into the rx buffer, valid until the
  response completes.
- **tx**: everything outbound goes through the slot's tx region using
  the pool's short-write contract: write what the kernel takes, keep a
  cursor, continue from `on_writable`. Static bodies never enter the tx
  buffer at all — they stream straight from the file source (§4).
- A slot serves one request at a time. Pipelined bytes beyond the
  current request stay in the rx buffer and are parsed after the
  response finishes (correct, but no concurrent handling).

### HttpLimits (all init-time)

| limit | default | on violation |
| --- | --- | --- |
| max connections | pool size | accept+close (`on_rejected`) |
| max request line | 2 KiB | 414 |
| max header block | 8 KiB | 431 |
| max header count | 32 | 431 |
| max body bytes | 64 KiB (buffered) / handler-declared (streamed) | 413 |
| max WS message | 64 KiB | close 1009 |
| header-read timeout | 10 s | 408 + close |
| keep-alive idle | 30 s | close |
| WS idle ping / drop | 30 s / 60 s | ping, then close 1001 |

## 3. HTTP parsing (M0)

Incremental push parser, one instance per slot, restartable per
request:

- Request line: method (enum: GET/HEAD/PUT/POST/OPTIONS — anything else
  → 501), target, version (`HTTP/1.1` required; `HTTP/1.0` accepted
  with keep-alive off).
- Target: percent-decoding of unreserved characters only, `+` left
  alone, dot-segment normalization (`..` collapse) BEFORE routing, query
  string split off and preserved raw. A target that escapes the root
  after normalization → 400.
- Headers: bounded count and bytes; names case-folded on comparison;
  known headers (Host, Content-Length, Connection, Upgrade, and the
  WS/conditional set) recognized into an indexed struct, the rest
  available by linear scan for handlers.
- Body framing: `Content-Length` only. `Transfer-Encoding` inbound →
  501. Missing length on PUT/POST → 411.
- Every limit violation maps to a specific status; the parser is a pure
  function of bytes — no I/O, no clock, no allocation — so it can be
  torture-tested byte-by-byte (every split point of every corpus entry
  must parse identically).

## 4. Static files from a manifest (M2)

Manifest is TOML, loaded once at startup:

```toml
[[route]]
uri = "/"
file = "site/index.html"
type = "text/html; charset=utf-8"

[[route]]
uri = "/app.js"
file = "site/app.js"
type = "application/javascript"
cache = "max-age=60"        # optional; omitted → no Cache-Control
```

- Exact-match URIs only (the widget app is a known, finite site); the
  table is sorted once and binary-searched. No globbing, no fallback
  file, no directory traversal at request time by construction.
- Each entry is opened at startup: `fstat` for size + `Last-Modified`,
  strong ETag from (size, mtime), then either **mmap** (default —
  zero-copy, page-cache-backed, fd closed after map) or **kept-fd
  pread** for entries above a size threshold or when mmap fails. The
  per-request serve is: headers into tx buffer, body chunks from the
  source through the short-write cursor. `HEAD` serves headers only;
  `If-None-Match` → 304.
- A manifest entry that fails to open at startup fails startup loudly
  (a control UI with missing assets is a broken deployment, not a
  runtime 404). Reload = restart, by design.

## 5. Dynamic handlers (M3)

Handlers register before `start()` (fixed table): method + exact path.
The API is streaming-first so a body larger than the rx buffer never
forces a bigger buffer:

```cpp
class HttpHandler {
  // Decide fate from the request line + headers. Return: accept
  // (buffered — server assembles ≤ max-body bytes and calls
  // on_complete once), accept_streaming (on_body_chunk per read), or
  // a rejection status (405/413/...).
  virtual Disposition on_headers(Request const&, ResponseWriter&) = 0;
  virtual void on_body_chunk(Request const&, span<uint8_t const>) {}
  virtual void on_complete(Request const&, ResponseWriter&) = 0;
};
```

`ResponseWriter` builds status + headers into the tx region and body
either as a single span (`Content-Length` known) or as writer-driven
chunks with explicit length declared up front — outbound chunked
encoding is an open decision (§9), not assumed. Handlers run on the
reactor thread and must not block; a handler needing async completion
holds the slot and finishes from a later tick (the widget bridge will
use this for 1722.1 round trips).

## 6. WebSocket (M4)

- Upgrade path: `GET` + `Upgrade: websocket` + `Sec-WebSocket-Key` on a
  route registered as a WS endpoint → 101 with `Sec-WebSocket-Accept`;
  the slot flips to WS mode and leaves HTTP parsing permanently.
- Frame codec: client→server frames MUST be masked (else close 1002);
  server frames never masked. Fragmented messages reassemble into the
  slot's fixed message buffer (cap → close 1009). Control frames
  (ping/pong/close, ≤125 bytes, never fragmented) are handled between
  fragments per RFC. Close handshake both directions; idle ping policy
  from HttpLimits.
- Endpoint API mirrors the transport shape: `on_ws_open(slot)`,
  `on_ws_message(slot, span, is_text)`, `on_ws_closed(slot)`, and
  `ws_send(slot, span, kind)` using the same short-write cursor —
  which forces the one honest design question early: a `ws_send` that
  doesn't fit is refused (`buffer_full`), and per-endpoint policy
  decides whether that drops a stale sample (fine for meter streams) or
  closes (for command channels). No hidden unbounded queue, ever.

### 6.1 SHA-1 + base64

Self-contained in `http_sha1.{hpp,cpp}`, used only for
`Sec-WebSocket-Accept`. RFC 3174 test vectors + the RFC 6455 worked
example (`dGhlIHNhbXBsZSBub25jZQ==` → `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`)
as unit tests. A comment states why this is not, and must never
become, a general hashing facility.

## 7. Milestones

Each lands with tests green in Debug and Release, `reformat.sh --check`
clean, through the ci/ flow.

- **M0 — parser.** `http_limits.hpp` + `http_parser` + torture tests:
  byte-split invariance over a corpus of valid requests; one asserted
  status per malformed/oversize case. Pure, I/O-free.
- **M1 — connection engine.** `HttpServer` on `TcpConnectionPool`:
  parse → route (stub router: 404 everything) → respond, keep-alive,
  pipelining-as-queueing, 408/431/timeouts on the injected clock.
  Acceptance: loopback tests with a raw test client (the
  `net_tcp_server_test` pattern) covering keep-alive reuse, slow-loris
  timeout, and oversize rejection; `curl -v` smoke.
- **M2 — manifest + static.** TOML manifest, mmap/pread sources,
  ETag/304, HEAD, startup failure on bad entries. Acceptance: serve a
  small real site to a browser; conditional-GET test; a
  1 MiB asset streams correctly through backpressure (nonblocking
  client, byte-exact verify — the Blaster test inverted).
- **M3 — handlers.** GET/PUT/POST dispatch, buffered and streaming
  bodies, 405/411/413. Acceptance: echo handler round-trips a body
  larger than the rx buffer via streaming; wrong-method and
  missing-length cases.
- **M4 — WebSocket.** Handshake + codec + endpoint API + echo endpoint.
  Acceptance: codec unit tests (masking, fragmentation, interleaved
  control frames, close); loopback WS echo through a hand-rolled
  masked client; browser smoke against the example server.
- **M5 — hardening.** Allocation gate: a test-interposed `operator new`
  counter proves zero allocations across a steady-state mixed workload
  (static GET, POST, WS echo) after `start()` — the module's
  reason-to-exist, enforced like the controlplane fan-out bench.
  Malformed-input fuzz corpus replayed through the pure parser.
  Throughput/latency bench with a regression gate.
- **M6 — the 1722.1 widget bridge (NOT in core).** In avb or
  atdecc-control: a WS subprotocol that pushes discovered entities'
  CONTROL descriptors as widget specs (the folded ranges, units, enum
  labels, and device names are exactly the metadata a widget needs),
  GET/SET over the socket, unsolicited notifications as live updates.
  Listed here only because it shapes M3/M4 API decisions: async
  handler completion, and the `ws_send` refusal policy for meter-rate
  streams.

## 8. Layering rule

`statusbar/http` may not name, include, or special-case anything from
avb or the control plane — the same discipline as `controlplane`'s
no-avb rule, pointing the other way. The widget server is a consumer;
if it needs a hook this module lacks, the hook must be justifiable for
a generic embedded site.

## 9. Open decisions

1. **Outbound chunked encoding** for dynamic responses vs
   `Content-Length`-required (compute-then-send within the tx region).
   Leaning: length-required in M3; add chunked only when a real
   handler needs unbounded output.
2. **Range requests** for static files (resumable downloads). Deferred
   unless the widget app ships large assets.
3. **`sm` vs enum** for the connection state machine — decide in M1 by
   writing it both ways on paper; the sm DSL wins only if the
   transition table stays readable.
4. **CORS / extra static headers**: probably a per-route `headers`
   table in the manifest rather than code.
5. **Auth**: out of scope for core; the front-end terminator or the M6
   layer owns it. Revisit only if a generic bearer-check hook proves
   necessary.
