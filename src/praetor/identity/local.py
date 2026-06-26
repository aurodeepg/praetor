"""Local identity backend — a gateway-held RSA keypair signs warrant tokens.

Zero-config and free: the gateway generates a keypair on construction and signs each
warrant's claims as an RS256 JWT. Good enough for a single-node gateway and the
demos; a SPIFFE/SPIRE backend for real fleet-wide workload identity can slot in
behind the same :class:`~praetor.identity.base.IdentityProvider` contract later.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from praetor.identity.base import IdentityProvider
from praetor.models import AgentIdentity, _uid

ISSUER = "praetor"


class LocalIdentityProvider(IdentityProvider):
    """Signs warrant tokens with an in-process RSA keypair."""

    def __init__(self, jwt_alg: str = "RS256") -> None:
        self.jwt_alg = jwt_alg
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._private_pem = self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._public_pem = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def issue_identity(self, name: str, trust: str = "unverified") -> AgentIdentity:
        return AgentIdentity(
            id=_uid(f"agent:{name}"),
            name=name,
            trust=trust,
            public_key=self._public_pem.decode(),
        )

    def sign(self, claims: dict[str, Any]) -> str:
        payload = {"iss": ISSUER, "iat": int(time.time()), **claims}
        return jwt.encode(payload, self._private_pem, algorithm=self.jwt_alg)

    def verify(self, token: str) -> dict[str, Any]:
        # Verify signature + issuer here; expiry/revocation are checked elsewhere so
        # that revocation can be instant rather than waiting on token TTL.
        return jwt.decode(
            token,
            self._public_pem,
            algorithms=[self.jwt_alg],
            issuer=ISSUER,
            options={"verify_exp": False},
        )

    def public_pem(self) -> str | None:
        return self._public_pem.decode()
