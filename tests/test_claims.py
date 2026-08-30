from hamcrest import assert_that, equal_to, greater_than, has_entries, has_entry

from elegant_jwt import ExpiringClaims, IssuedClaims, JwtClaims
from tests.fakes import FakeClock, FakeSignature


def test_returns_payload_as_json():
    assert_that(
        JwtClaims({"sub": "8128", "role": "navigator"}).json(),
        equal_to({"sub": "8128", "role": "navigator"}),
        "Claims must give back the payload they encapsulate",
    )


def test_stays_intact_after_mutation_of_json():
    claims = JwtClaims({"color": "vermilion"})
    claims.json()["color"] = "tampered"
    assert_that(
        claims.json(),
        equal_to({"color": "vermilion"}),
        "Claims must hand out a copy, never the original payload",
    )


def test_builds_token_through_signature():
    assert_that(
        JwtClaims({"sub": "4021"})
        .token(FakeSignature("head.body.seal", {"sub": "4021"}))
        .value(),
        equal_to("head.body.seal"),
        "Claims must build a token from the string the signature encoded",
    )


def test_adds_expiration_on_top_of_origin():
    assert_that(
        ExpiringClaims(JwtClaims({"sub": "77"}), 240, FakeClock(52000)).json(),
        equal_to({"sub": "77", "exp": 52240}),
        "Expiring claims must append the clock moment plus the lifetime",
    )


def test_adds_expiration_with_system_clock_by_default():
    assert_that(
        ExpiringClaims(JwtClaims({}), 15).json(),
        has_entry("exp", greater_than(1_000_000_000)),
        "Expiring claims must fall back to the system clock",
    )


def test_builds_expiring_token_through_signature():
    assert_that(
        ExpiringClaims(JwtClaims({"sub": "555"}), 90, FakeClock(700))
        .token(FakeSignature("aaa.bbb.ccc", {"sub": "555", "exp": 790}))
        .value(),
        equal_to("aaa.bbb.ccc"),
        "Expiring claims must still build a token through the signature",
    )


def test_adds_issue_claims_on_top_of_origin():
    assert_that(
        IssuedClaims(JwtClaims({"sub": "306"}), "acme", FakeClock(81000)).json(),
        equal_to({"sub": "306", "iat": 81000, "iss": "acme"}),
        "Issued claims must append the issue moment and the issuer name",
    )


def test_adds_issue_claims_with_system_clock_by_default():
    assert_that(
        IssuedClaims(JwtClaims({}), "umbrella").json(),
        has_entry("iat", greater_than(1_000_000_000)),
        "Issued claims must fall back to the system clock",
    )


def test_builds_issued_token_through_signature():
    assert_that(
        IssuedClaims(JwtClaims({"sub": "12"}), "wonka", FakeClock(400))
        .token(FakeSignature("xx.yy.zz", {"sub": "12"}))
        .value(),
        equal_to("xx.yy.zz"),
        "Issued claims must still build a token through the signature",
    )


def test_stacks_decorators_into_one_payload():
    assert_that(
        IssuedClaims(
            ExpiringClaims(JwtClaims({"sub": "601"}), 30, FakeClock(9000)),
            "initech",
            FakeClock(9000),
        ).json(),
        has_entries(sub="601", exp=9030, iat=9000, iss="initech"),
        "Stacked decorators must merge their claims into one payload",
    )
