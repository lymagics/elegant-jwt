from hamcrest import (
    assert_that,
    calling,
    equal_to,
    greater_than,
    has_entries,
    has_entry,
    is_not,
    matches_regexp,
    raises,
)

from elegant_jwt import (
    ExpiringClaims,
    IssuedClaims,
    JtiClaims,
    JwtClaims,
    NotBeforeClaims,
)
from tests.fakes import BrokenSignature, FakeClock, FakeSignature


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


def test_stays_intact_after_mutation_of_nested_list_in_json():
    claims = JwtClaims({"sub": "3", "roles": ["viewer"]})
    claims.json()["roles"].append("root")
    assert_that(
        claims.json(),
        equal_to({"sub": "3", "roles": ["viewer"]}),
        "Claims must hand out a copy whose nested lists are independent",
    )


def test_stays_intact_after_mutation_of_nested_dict_in_json():
    claims = JwtClaims({"sub": "19", "scope": {"read": {"docs": True}}})
    claims.json()["scope"]["read"]["docs"] = False
    assert_that(
        claims.json(),
        equal_to({"sub": "19", "scope": {"read": {"docs": True}}}),
        "Claims must hand out a copy whose nested dicts are independent",
    )


def test_builds_token_through_signature():
    assert_that(
        JwtClaims({"sub": "4021"})
        .token(FakeSignature("head.body.seal", {"sub": "4021"}))
        .value(),
        equal_to("head.body.seal"),
        "Claims must build a token from the string the signature encoded",
    )


def test_complains_in_user_words_when_signing_fails():
    assert_that(
        calling(JwtClaims({"sub": "6600"}).token).with_args(
            BrokenSignature("snapped quill")
        ),
        raises(Exception, "The claims could not be signed"),
        "Claims must complain in user words when the signature cannot encode them",
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


def test_adds_not_before_on_top_of_origin():
    assert_that(
        NotBeforeClaims(
            JwtClaims({"sub": "913"}), 3599, FakeClock(1_700_000_001)
        ).json(),
        equal_to({"sub": "913", "nbf": 1_700_003_600}),
        "Not-before claims must append the clock moment plus the delay",
    )


def test_adds_not_before_with_system_clock_by_default():
    assert_that(
        NotBeforeClaims(JwtClaims({}), 0).json(),
        has_entry("nbf", greater_than(1_000_000_000)),
        "Not-before claims must fall back to the system clock",
    )


def test_builds_not_before_token_through_signature():
    assert_that(
        NotBeforeClaims(JwtClaims({"sub": "27"}), 1, FakeClock(65535))
        .token(FakeSignature("h.p.s", {"sub": "27", "nbf": 65536}))
        .value(),
        equal_to("h.p.s"),
        "Not-before claims must still build a token through the signature",
    )


def test_stacks_not_before_with_other_decorators():
    assert_that(
        NotBeforeClaims(
            IssuedClaims(
                ExpiringClaims(JwtClaims({"sub": "808"}), 120, FakeClock(31337)),
                "globex",
                FakeClock(31337),
            ),
            45,
            FakeClock(31337),
        ).json(),
        has_entries(sub="808", exp=31457, iat=31337, iss="globex", nbf=31382),
        "Not-before claims must merge with the claims of stacked decorators",
    )


def test_adds_identity_on_top_of_origin():
    assert_that(
        JtiClaims(JwtClaims({"sub": "1024"}), "ticket-0x7f").json(),
        equal_to({"sub": "1024", "jti": "ticket-0x7f"}),
        "Jti claims must append the identity they were given",
    )


def test_adds_uuid_identity_by_default():
    assert_that(
        JtiClaims(JwtClaims({})).json(),
        has_entry(
            "jti",
            matches_regexp(
                "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
            ),
        ),
        "Jti claims must fall back to a random version 4 UUID",
    )


def test_gives_each_object_its_own_identity_by_default():
    assert_that(
        JtiClaims(JwtClaims({"sub": "2048"})).json()["jti"],
        is_not(equal_to(JtiClaims(JwtClaims({"sub": "2048"})).json()["jti"])),
        "Two jti claims built without an identity must not share one",
    )


def test_builds_identified_token_through_signature():
    assert_that(
        JtiClaims(JwtClaims({"sub": "4096"}), "nonce-9")
        .token(FakeSignature("id.en.tity", {"sub": "4096", "jti": "nonce-9"}))
        .value(),
        equal_to("id.en.tity"),
        "Jti claims must still build a token through the signature",
    )


def test_stacks_identity_with_other_decorators():
    assert_that(
        JtiClaims(
            IssuedClaims(
                ExpiringClaims(JwtClaims({"sub": "8192"}), 600, FakeClock(123456)),
                "hooli",
                FakeClock(123456),
            ),
            "one-shot-77",
        ).json(),
        has_entries(sub="8192", exp=124056, iat=123456, iss="hooli", jti="one-shot-77"),
        "Jti claims must merge with the claims of stacked decorators",
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
