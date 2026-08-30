from hamcrest import assert_that, calling, equal_to, is_, raises

from elegant_jwt import JwtToken, StrictToken
from tests.fakes import BrokenSignature, FakeClock, FakeSignature


def test_builds_claims_from_decoded_payload():
    assert_that(
        JwtToken("one.two.three", FakeSignature("one.two.three", {"sub": "1917"}))
        .claims()
        .json(),
        equal_to({"sub": "1917"}),
        "Token must build claims from the payload the signature decoded",
    )


def test_exposes_raw_encoded_value():
    assert_that(
        JwtToken("alpha.beta.gamma", FakeSignature("alpha.beta.gamma", {})).value(),
        equal_to("alpha.beta.gamma"),
        "Token must expose the raw encoded string",
    )


def test_reports_remaining_validity_before_expiration():
    assert_that(
        JwtToken(
            "v.a.l",
            FakeSignature("v.a.l", {"exp": 6100}),
            FakeClock(6000),
        ).validity(),
        equal_to(100),
        "Token must report the seconds left until expiration",
    )


def test_reports_zero_validity_after_expiration():
    assert_that(
        JwtToken(
            "o.l.d",
            FakeSignature("o.l.d", {"exp": 300}),
            FakeClock(9500),
        ).validity(),
        equal_to(0),
        "Token must never report a negative validity",
    )


def test_expires_at_the_exact_expiration_moment():
    assert_that(
        JwtToken(
            "e.d.ge",
            FakeSignature("e.d.ge", {"exp": 47000}),
            FakeClock(47000),
        ).expired(),
        is_(True),
        "Token must count itself expired at the very expiration moment",
    )


def test_stays_fresh_before_expiration():
    assert_that(
        JwtToken(
            "f.r.esh", FakeSignature("f.r.esh", {"exp": 88000}), FakeClock(70)
        ).expired(),
        is_(False),
        "Token must stay fresh while the expiration is ahead",
    )


def test_complains_about_invalid_token():
    assert_that(
        calling(JwtToken("br.ok.en", BrokenSignature("forged seal")).claims),
        raises(Exception, "The access token is not valid"),
        "Token must complain in user words when decoding fails",
    )


def test_complains_about_missing_expiration_claim():
    assert_that(
        calling(
            JwtToken(
                "n.o.exp",
                FakeSignature("n.o.exp", {"sub": "2001"}),
                FakeClock(1200),
            ).validity
        ),
        raises(Exception, "no expiration claim"),
        "Token must complain when the expiration claim is absent",
    )


def test_refuses_claims_of_expired_token():
    assert_that(
        calling(
            StrictToken(
                JwtToken(
                    "de.a.d",
                    FakeSignature("de.a.d", {"exp": 100}),
                    FakeClock(64000),
                )
            ).claims
        ),
        raises(Exception, "expired"),
        "Strict token must refuse to give claims after expiration",
    )


def test_passes_claims_of_fresh_token():
    assert_that(
        StrictToken(
            JwtToken(
                "li.v.e",
                FakeSignature("li.v.e", {"sub": "451", "exp": 99000}),
                FakeClock(3),
            )
        )
        .claims()
        .json(),
        equal_to({"sub": "451", "exp": 99000}),
        "Strict token must pass the claims of a fresh token through",
    )


def test_mirrors_value_of_origin():
    assert_that(
        StrictToken(JwtToken("mir.r.or", FakeSignature("mir.r.or", {}))).value(),
        equal_to("mir.r.or"),
        "Strict token must mirror the raw value of its origin",
    )


def test_mirrors_validity_of_origin():
    assert_that(
        StrictToken(
            JwtToken(
                "s.a.me",
                FakeSignature("s.a.me", {"exp": 5300}),
                FakeClock(5100),
            )
        ).validity(),
        equal_to(200),
        "Strict token must mirror the validity of its origin",
    )


def test_mirrors_freshness_of_origin():
    assert_that(
        StrictToken(
            JwtToken(
                "y.o.ung",
                FakeSignature("y.o.ung", {"exp": 32000}),
                FakeClock(15),
            )
        ).expired(),
        is_(False),
        "Strict token must mirror the freshness of its origin",
    )
