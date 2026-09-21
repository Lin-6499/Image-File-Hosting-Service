"""Tests for the HMAC signing module.

These are the highest-value tests in the suite: everything about link expiry
and purpose separation is enforced here.
"""

from __future__ import annotations

import pytest

from app.signing import (
    SignatureError,
    clamp_ttl,
    sign,
    verify,
)

SECRET = "unit-test-secret"


class TestSignAndVerify:
    def test_roundtrip_succeeds(self):
        exp = 2_000_000_000
        sig = sign("abc123", exp, "dl", SECRET)
        # Should not raise.
        verify("abc123", exp, "dl", sig, SECRET, now=exp - 100)

    def test_wrong_secret_rejected(self):
        sig = sign("abc123", 2_000_000_000, "dl", SECRET)
        with pytest.raises(SignatureError) as e:
            verify("abc123", 2_000_000_000, "dl", sig, "other-secret", now=1_999_000_000)
        assert e.value.reason == "bad_signature"

    def test_tampered_file_id_rejected(self):
        sig = sign("abc123", 2_000_000_000, "dl", SECRET)
        with pytest.raises(SignatureError):
            verify("abc124", 2_000_000_000, "dl", sig, SECRET, now=1_999_000_000)

    def test_tampered_expiry_rejected(self):
        sig = sign("abc123", 2_000_000_000, "dl", SECRET)
        with pytest.raises(SignatureError):
            verify("abc123", 2_100_000_000, "dl", sig, SECRET, now=1_999_000_000)

    def test_purpose_escalation_blocked(self):
        """The core privilege-escalation guard.

        An image link must not be convertible into a download link by editing
        the query parameter, even though the file_id and expiry are unchanged.
        """
        exp = 2_000_000_000
        img_sig = sign("abc123", exp, "img", SECRET)
        with pytest.raises(SignatureError):
            verify("abc123", exp, "dl", img_sig, SECRET, now=exp - 100)

    def test_field_concatenation_ambiguity(self):
        """Newline separators must prevent cross-field collisions.

        Without a delimiter, ("a1", "2") and ("a12", "") hash identically.
        """
        sig_a = sign("a1", 2, "dl", SECRET)
        sig_b = sign("a12", 22, "dl", SECRET)
        assert sig_a != sig_b

    def test_empty_purpose_differs_from_dl(self):
        assert sign("f", 100, "", SECRET) != sign("f", 100, "dl", SECRET)


class TestExpiry:
    def test_expired_rejected(self):
        exp = 1_000
        sig = sign("abc", exp, "dl", SECRET)
        # clock_skew=0 to isolate expiry from the drift allowance.
        with pytest.raises(SignatureError) as e:
            verify("abc", exp, "dl", sig, SECRET, now=exp + 1, clock_skew=0)
        assert e.value.reason == "expired"

    def test_default_skew_grants_small_grace(self):
        """The default 5s skew intentionally extends the window slightly.

        Documented behaviour, not a bug: it stops a server whose clock runs a
        few seconds fast from rejecting links it just issued.
        """
        exp = 1_000
        sig = sign("abc", exp, "dl", SECRET)
        verify("abc", exp, "dl", sig, SECRET, now=exp + 1)  # no raise
        with pytest.raises(SignatureError):
            verify("abc", exp, "dl", sig, SECRET, now=exp + 6)

    def test_exactly_at_expiry_allowed(self):
        exp = 1_000
        sig = sign("abc", exp, "dl", SECRET)
        verify("abc", exp, "dl", sig, SECRET, now=exp, clock_skew=0)

    def test_clock_skew_tolerated(self):
        """A server running slightly fast must not reject fresh links."""
        exp = 1_000
        sig = sign("abc", exp, "dl", SECRET)
        verify("abc", exp, "dl", sig, SECRET, now=exp + 3, clock_skew=5)

    def test_beyond_clock_skew_rejected(self):
        exp = 1_000
        sig = sign("abc", exp, "dl", SECRET)
        with pytest.raises(SignatureError):
            verify("abc", exp, "dl", sig, SECRET, now=exp + 10, clock_skew=5)

    def test_expiry_checked_before_signature(self):
        """Expiry must be reported even with a garbage signature.

        Ordering matters for callers: 410 (re-issue) is actionable, 403 is not.
        """
        with pytest.raises(SignatureError) as e:
            verify("abc", 1_000, "dl", "garbage", SECRET, now=9_999)
        assert e.value.reason == "expired"


class TestClampTtl:
    def test_none_returns_default(self):
        assert clamp_ttl(None, 3600, 86400) == 3600

    def test_within_range_preserved(self):
        assert clamp_ttl(600, 3600, 86400) == 600

    def test_above_max_clamped(self):
        """Prevents a caller from issuing a de-facto permanent link."""
        assert clamp_ttl(10**9, 3600, 86400) == 86400

    def test_negative_clamped_to_one(self):
        assert clamp_ttl(-500, 3600, 86400) == 1

    def test_zero_clamped_to_one(self):
        assert clamp_ttl(0, 3600, 86400) == 1

    def test_exactly_max_preserved(self):
        assert clamp_ttl(86400, 3600, 86400) == 86400


class TestSignatureStability:
    def test_signature_is_deterministic(self):
        a = sign("f", 123, "dl", SECRET)
        b = sign("f", 123, "dl", SECRET)
        assert a == b

    def test_signature_is_url_safe(self):
        sig = sign("file-_id", 123, "dl", SECRET)
        assert "+" not in sig and "/" not in sig and "=" not in sig

    def test_signature_length_constant(self):
        """SHA-256 -> 32 bytes -> 43 base64url chars without padding."""
        assert len(sign("f", 123, "dl", SECRET)) == 43
