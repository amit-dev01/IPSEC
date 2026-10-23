"""Optional passive live-capture agent — deployed separately, never by the API.

The API service contains no capture capability. This package runs only on
explicitly authorized hosts, accepts only admin-allowlisted interface IDs and
capture profiles, captures passively for a bounded time/size, and uploads via
the normal authenticated ingestion API (SHA-256 verified server-side).
"""
