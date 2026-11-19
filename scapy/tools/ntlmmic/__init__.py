"""Offline NTLM handshake integrity diagnostics.

This package separates three notions that passive NTLM analysis often
conflates:

- presence: a MIC field or a channel-binding AV pair is present on the wire;
- verifiability: the material required to actually check the value exists;
- verdict: the cryptographic / SSP-level check succeeded, failed, or could not
  be decided.

It only performs offline inspection of captured NTLMSSP tokens and, when the
defender explicitly supplies key material, local MIC recomputation. It never
performs network authentication, relay, or password recovery.
"""

__all__ = [
    "analysis",
    "evidence",
    "synthdata",
]
