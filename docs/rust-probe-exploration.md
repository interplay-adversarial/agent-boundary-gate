# Standalone Rust HTTP probe exploration

Status: proposed follow-up, 2026-10-12. No Rust executable or live qualification
is delivered by this exploration. Python remains the default; Perl supports
images that lack Python but provide its required modules. See the
[live-rig handoff](live-rig-handoff.md) for that compatibility rationale.

## Proposed scope

A small Cargo package under `probes/http/` could provide a dedicated executable
without a Python or Perl runtime prerequisite. Keep its source in this repository
and select it explicitly in the OpenShell backend after conformance testing.
Distribution into a pinned workload image and executable policy authorization
remain necessary; a standalone binary is not automatically available in a stock image.

Start with the Rust standard library and the same fixed direct HTTP request:
`GET /probe`, `Host`, `X-Gate-Attempt` and `Connection: close`. Read at most one
response byte. Do not add arbitrary destinations/paths, proxy configuration,
redirect handling, TLS or general response parsing to this increment. Validate
bounded ASCII arguments before networking, including header-safe identifiers,
numeric port bounds and the one-to-thirty-second action timeout.

Connection rejection or a request timeout can complete an attempted probe.
Completion never proves allowed or denied egress: independent correlated receiver
events and the positive control remain the outcome oracle. Invalid arguments or
runtime failures must not emit a completion marker.

## Deadline and resource requirements

DNS is the principal unresolved design choice. `ToSocketAddrs` can block while
resolving; `TcpStream::connect_timeout` takes an already resolved address. Read
and write timeouts bound individual operations, not the complete probe. Use one
monotonic budget and recompute remaining time for connection, write and read;
bound address attempts, buffers and output. Retain sandbox-side termination and
the controller deadline. A timed helper thread that leaves a blocked resolver
running is insufficient. See [address resolution](https://doc.rust-lang.org/std/net/trait.ToSocketAddrs.html)
and [TCP timeout APIs](https://doc.rust-lang.org/std/net/struct.TcpStream.html).

An explicitly labeled IP-only experiment can avoid resolver blocking. It changes
hostname-policy and DNS coverage; resolving outside the sandbox cannot substitute
for exercising sandbox DNS. A hostname-capable release needs a demonstrated
bounded-resolution or externally enforced termination design.

## Builds, distribution and trust

Explore Linux `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` artifacts.
Request static CRT linkage and inspect each artifact for dynamic loader/library
requirements; compilation alone does not establish static linkage. GNU/glibc
builds are an alternative for pinned images with documented ABI requirements.
Run conformance tests on each supported architecture; cross-compilation alone
does not establish runtime compatibility. See [Rust target support](https://doc.rust-lang.org/stable/rustc/platform-support.html)
and [CRT linkage](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes).

Pin the compiler/build environment, source commit, binary digest and workload
image digest. Publish checksums and provenance; remap build paths and scan binary
contents for private data. Install the verified artifact before sandbox creation
and bind it into trusted configuration. Authorize the exact executable path and
review process-ancestor permissions against the selected OpenShell revision.
Runtime executable trust does not replace an externally trusted artifact pin;
see [OpenShell executable identity guidance](https://github.com/NVIDIA/OpenShell/blob/main/docs/security/best-practices.mdx).

## Acceptance and next increment

Share receiver conformance tests across Python, Perl and Rust: exact correlated
request, IPv4/IPv6 authority, proxy isolation, no redirects, malformed input
rejected before connection, and no security conclusion from completion alone.
Add blocked DNS, stalled connection/read/write, address-count/resource limits,
cancellation and whole-probe deadline tests. Add Cargo formatting, Clippy,
unit/conformance checks and toolchain/advisory maintenance; using only the standard
library does not remove compiler or standard-library security obligations.

First prototype the bounded IP-literal request and artifact builds without changing
signed schemas or gate policy. Resolve hostname coverage and distribution before
adding a supported backend runtime option. This belongs to COMPAT-04, with DEV-01
distribution checks and QUAL-01 pinned-image testing. Release eligibility stays off.
