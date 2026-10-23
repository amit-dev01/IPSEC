# ADR-0001: Separate API and packet-analysis worker

## Context
PCAP/PCAPNG files are untrusted input parsed by complex dissectors. The API is
internet-facing and latency-sensitive; parsing is CPU/memory-heavy and long-running.

## Decision
Run parsing in a separate Celery worker service with its own container image. The API
never parses captures and contains no packet tools (no TShark/tcpdump). The API
enqueues job IDs only; the worker fetches the capture, verifies SHA-256, parses under
time/packet/resource limits, and writes metadata/findings back.

## Consequences
+ A parser exploit or resource bomb is contained in a non-root, egress-less worker
  with scoped credentials (threat model T1/T5); the API stays responsive.
+ Independent scaling and timeouts; TShark exists in exactly one image.
− Two deployments to operate; results are asynchronous (job lifecycle), not inline.
