"""M10: the semantic matcher + provider-neutral backends + selection factory.

The matcher logic is tested against injected fake embedder/generator (no network); the
HTTP providers are tested against ``httpx.MockTransport`` (no daemon). Selection always
degrades to the deterministic matcher when a backend is missing/unavailable.
"""

import json

import httpx

from praetor.gateway import Gateway
from praetor.matcher import DeterministicMatcher, SemanticMatcher, make_matcher
from praetor.matcher import factory as factory_mod
from praetor.matcher.providers import OllamaEmbedder, OllamaGenerator, OpenAICompatEmbedder
from praetor.matcher.providers.embedder import Embedder
from praetor.matcher.providers.generator import Generator
from praetor.models import Capability

ROSTER = [
    ("containment", Capability(name="net.isolate", description="isolate a host from the network",
                               targets="host:*")),
    ("forensics", Capability(name="logs.read", description="read and inspect host and app logs",
                             targets="logs:*")),
    ("threat-intel", Capability(name="intel.lookup", description="enrich an indicator")),
]


class FakeEmbedder(Embedder):
    """Deterministic bag-of-words vectors over the batch vocab — cosine ≈ token overlap,
    so the semantically-closest capability ranks first, with no model."""

    def __init__(self, *, ok: bool = True) -> None:
        self.name = "fake"
        self._ok = ok

    def available(self) -> bool:
        return self._ok

    def embed(self, texts: list[str]) -> list[list[float]]:
        toks = [set(t.lower().replace(".", " ").replace("-", " ").split()) for t in texts]
        vocab = sorted(set().union(*toks)) if toks else []
        return [[1.0 if w in ts else 0.0 for w in vocab] for ts in toks]


class FakeGenerator(Generator):
    def __init__(self, payload: str) -> None:
        self.name = "fakegen"
        self._payload = payload

    def generate(self, prompt: str, *, schema=None, temperature: float = 0.0) -> str:
        return self._payload


# ── semantic ranking ─────────────────────────────────────────────────────────


def test_semantic_ranks_by_cosine_similarity():
    m = SemanticMatcher(FakeEmbedder())
    res = m.match("isolate the compromised host db-prod-12", ROSTER)
    assert res.backend.startswith("semantic[")
    assert res.best.capability.name == "net.isolate"
    assert [r.score for r in res.ranked] == sorted((r.score for r in res.ranked), reverse=True)


def test_semantic_empty_registry_proposes_nothing():
    res = SemanticMatcher(FakeEmbedder()).match("anything", [])
    assert res.ranked == [] and res.proposal is None


# ── scope proposal: generator first, deterministic fallback ──────────────────


def test_proposal_falls_back_to_deterministic_without_a_generator():
    res = SemanticMatcher(FakeEmbedder()).match("read and inspect the auth logs", ROSTER)
    prop = res.proposal
    assert prop.capability == "logs.read"
    assert "write" in prop.excludes and "delete" in prop.excludes   # read-only lockout
    assert "cosine" in prop.rationale                                # semantic prefix


def test_proposal_uses_the_generator_when_it_returns_valid_json():
    gen = FakeGenerator('{"target": "host-9", "read_only": false, "rationale": "isolate it"}')
    res = SemanticMatcher(FakeEmbedder(), generator=gen).match("isolate host-9", ROSTER)
    prop = res.proposal
    assert prop.scope == {"target": "host-9"} and prop.excludes == []
    assert "fakegen" in prop.rationale


def test_proposal_falls_back_when_generator_output_is_unparseable():
    res = SemanticMatcher(FakeEmbedder(), generator=FakeGenerator("not json")).match(
        "isolate the compromised host host-9", ROSTER)
    # deterministic extractor still yields a sane, target-scoped proposal
    assert res.proposal.scope == {"target": "host-9"}


# ── factory + graceful fallback ──────────────────────────────────────────────


def test_factory_specs_parse_to_the_right_backends():
    e = factory_mod.make_embedder("ollama:qwen3-embedding:0.6b")
    assert isinstance(e, OllamaEmbedder) and e.model == "qwen3-embedding:0.6b"
    g = factory_mod.make_generator("ollama:qwen3:0.6b")
    assert isinstance(g, OllamaGenerator) and g.model == "qwen3:0.6b"
    assert isinstance(factory_mod.make_embedder("openai:text-embedding-3-small"),
                      OpenAICompatEmbedder)
    assert factory_mod.make_embedder("bogus:x") is None


def test_make_matcher_without_config_is_deterministic(monkeypatch):
    monkeypatch.delenv("PRAETOR_EMBEDDER", raising=False)
    monkeypatch.delenv("PRAETOR_GENERATOR", raising=False)
    assert isinstance(make_matcher(), DeterministicMatcher)


def test_make_matcher_degrades_when_embedder_unavailable(monkeypatch):
    monkeypatch.setattr(factory_mod, "make_embedder", lambda spec: FakeEmbedder(ok=False))
    assert isinstance(make_matcher(embedder_spec="ollama:whatever"), DeterministicMatcher)


def test_make_matcher_builds_semantic_when_embedder_available(monkeypatch):
    monkeypatch.setattr(factory_mod, "make_embedder", lambda spec: FakeEmbedder(ok=True))
    monkeypatch.setattr(factory_mod, "make_generator", lambda spec: None)
    m = make_matcher(embedder_spec="ollama:whatever")
    assert isinstance(m, SemanticMatcher)


# ── gateway integration ──────────────────────────────────────────────────────


def test_gateway_accepts_a_semantic_matcher():
    gw = Gateway(matcher=SemanticMatcher(FakeEmbedder()))
    gw.register_agent("containment", capabilities=[ROSTER[0][1]])
    gw.register_agent("forensics", capabilities=[ROSTER[1][1]])
    res = gw.match("isolate the compromised host host-9")
    assert res.proposal.agent == "containment" and res.proposal.scope == {"target": "host-9"}


# ── providers over httpx.MockTransport (no daemon) ───────────────────────────


def test_ollama_embedder_request_shape_and_availability():
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.url.path == "/api/tags":
            return httpx.Response(200, json={"models": []})
        if req.url.path == "/api/embeddings":
            return httpx.Response(200, json={"embedding": [0.1, 0.2, 0.3]})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x")
    emb = OllamaEmbedder("qwen3-embedding:0.6b", host="http://x", client=client)
    assert emb.available() is True
    vecs = emb.embed(["hello"])
    assert vecs == [[0.1, 0.2, 0.3]]
    assert seen[-1].url.path == "/api/embeddings"


def test_ollama_embedder_unavailable_when_daemon_refuses():
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    client = httpx.Client(transport=httpx.MockTransport(boom), base_url="http://x")
    assert OllamaEmbedder("m", host="http://x", client=client).available() is False


def test_ollama_generator_posts_prompt_and_schema():
    captured = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/generate":
            captured.update(json.loads(req.content))
            return httpx.Response(200, json={"response": '{"read_only": true, "rationale": "ok"}'})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x")
    gen = OllamaGenerator("qwen3:0.6b", host="http://x", client=client)
    out = gen.generate("prompt", schema={"type": "object"})
    assert '"read_only": true' in out
    assert captured["model"] == "qwen3:0.6b" and captured["format"] == {"type": "object"}
    assert captured["options"]["temperature"] == 0.0


def test_openai_compat_embedder_sends_bearer_and_input_list():
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"data": [
            {"index": 0, "embedding": [1.0]}, {"index": 1, "embedding": [2.0]}]})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x")
    emb = OpenAICompatEmbedder("text-embedding-3-small", base_url="http://x/v1",
                               api_key="sk-test", client=client)
    assert emb.available() is True
    assert emb.embed(["a", "b"]) == [[1.0], [2.0]]
    assert seen[0].headers["authorization"] == "Bearer sk-test"


def test_openai_compat_unavailable_without_key():
    assert OpenAICompatEmbedder("m", api_key=None).available() is False
