"""Container image digests: is this tag still the image we are running?

The instrument is `docker buildx imagetools inspect` and not `docker manifest inspect -v` —
measured on a freshly pulled image, the latter's first digest never equals the image's own
RepoDigest, so it would report every image stale for ever (design rule 6, decision D5).

This module holds the *pure* half: classifying what the registry answered. The shell half
lives in ``hostprobe.IMAGE_BLOCK``; it emits the raw answer and the classification happens
here, so the one thing that turns a refusal into a false all-clear is unit-tested.
"""
from __future__ import annotations

# Strings `docker buildx imagetools inspect` prints when it did not answer with a digest.
# The same table the routine shipped, kept in one place so a new registry error is a test,
# not a guess: 429 is a rate limit, everything else that is not a digest is "other".
_RATE_LIMIT = ("429", "toomanyrequests", "too many requests")
_NO_SUCH_IMAGE = ("pull access denied", "manifest unknown", "not found", "404")


def classify(raw: str) -> str:
    """A registry answer -> a digest, or ``err:rate-limited`` / ``err:no-such-image`` / ``err:other``.

    Short codes, because a message truncated into a payload loses the token that mattered
    (rule 5): the code is what the verdict reads, the raw text goes into ``detail``.
    """
    text = (raw or "").strip()
    if text.startswith("sha256:"):
        return text
    low = text.lower()
    if any(token in low for token in _RATE_LIMIT):
        return "err:rate-limited"
    if any(token in low for token in _NO_SUCH_IMAGE):
        return "err:no-such-image"
    return "err:other"


def detail(raw: str, limit: int = 120) -> str:
    """The registry's own words, bounded — evidence for the GAPS panel, never a verdict."""
    text = " ".join((raw or "").split())
    return text[:limit]
