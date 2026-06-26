"""M2: local keypair identity — verifiable agent identity + RS256-signed tokens."""

import jwt
import pytest

from praetor.identity import IdentityProvider, LocalIdentityProvider
from praetor.models import AgentIdentity, Warrant


@pytest.fixture
def idp() -> LocalIdentityProvider:
    return LocalIdentityProvider()


def test_local_provider_satisfies_the_contract(idp):
    assert isinstance(idp, IdentityProvider)
    assert idp.jwt_alg == "RS256"
    assert "BEGIN PUBLIC KEY" in idp.public_pem()


def test_issue_identity_is_namespaced_and_carries_the_public_key(idp):
    ident = idp.issue_identity("containment", trust="internal")
    assert isinstance(ident, AgentIdentity)
    assert ident.name == "containment"
    assert ident.trust == "internal"
    assert ident.id.startswith("agent:containment:")
    assert ident.public_key == idp.public_pem()


def test_issued_ids_are_unique(idp):
    a = idp.issue_identity("forensics")
    b = idp.issue_identity("forensics")
    assert a.id != b.id


def test_sign_verify_round_trip_carries_claims_and_issuer(idp):
    token = idp.sign({"sub": "agent:containment:1a2b3c4d", "cap": "net.isolate"})
    claims = idp.verify(token)
    assert claims["sub"] == "agent:containment:1a2b3c4d"
    assert claims["cap"] == "net.isolate"
    assert claims["iss"] == "praetor"
    assert "iat" in claims


def test_token_carries_a_warrants_claims(idp):
    ident = idp.issue_identity("containment", trust="internal")
    w = Warrant(
        subject=ident.id,
        on_behalf_of="incident://ir-4821",
        capability="net.isolate",
        scope={"target": "host-9"},
        issued_at=0,
        expires_at=600,
    )
    token = idp.sign(w.model_dump(include={"wid", "subject", "capability", "scope"}))
    claims = idp.verify(token)
    assert claims["subject"] == ident.id
    assert claims["capability"] == "net.isolate"
    assert claims["scope"] == {"target": "host-9"}


def test_tampered_token_is_rejected(idp):
    token = idp.sign({"sub": "x"})
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    with pytest.raises(jwt.InvalidSignatureError):
        idp.verify(tampered)


def test_token_from_another_keypair_is_rejected(idp):
    other = LocalIdentityProvider()
    token = other.sign({"sub": "x"})
    with pytest.raises(jwt.InvalidSignatureError):
        idp.verify(token)


def test_wrong_issuer_is_rejected(idp):
    # A validly-signed token from this key but with a foreign issuer must not verify.
    forged = jwt.encode({"iss": "evil", "sub": "x"}, idp._private_pem, algorithm="RS256")
    with pytest.raises(jwt.InvalidIssuerError):
        idp.verify(forged)


def test_expiry_is_not_enforced_at_verify(idp):
    # Signature proves issuance; liveness (expiry/revocation) is a separate concern.
    token = idp.sign({"sub": "x", "exp": 1})  # long past
    assert idp.verify(token)["sub"] == "x"
