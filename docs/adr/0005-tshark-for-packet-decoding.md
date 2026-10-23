# ADR-0005: TShark for packet decoding (worker image only)

## Context
Deterministic decoding of PCAP/PCAPNG (IKEv2/ESP framing, proposals, SPIs, sequence
data) requires a mature dissector. Writing a parser from scratch would be less
reliable and less safe. TShark's dissectors are also a known attack surface.

## Decision
Use TShark inside the worker image only — never in the API image. Invocation is a
fixed argument vector built in code: input comes from a server-generated temp path,
output fields are code-selected, and **no user-supplied arguments, display filters,
capture interfaces, or decryption/key options are accepted**. Runs are bounded by
timeout, packet-count cap, and temp-disk quota; raw stderr is not persisted.

## Consequences
+ Best-available deterministic decoding and PCAPNG support.
− Dissector vulnerabilities are the primary RCE surface; mitigated by ADR-0001
  isolation, non-root execution, egress-less networking, and patched image rebuilds.
