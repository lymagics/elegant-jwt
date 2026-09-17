from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from hamcrest import assert_that, calling, equal_to, has_entry, raises
from hypothesis import given
from hypothesis import strategies as st

from elegant_jwt import AudienceSignature, Es256, Hs256, Rs256
from tests.fakes import FakeSignature


@given(
    st.dictionaries(
        st.text(min_size=1).filter(
            lambda name: name not in {"exp", "nbf", "iat", "aud"}
        ),
        st.text(),
    )
)
def test_restores_any_payload_after_roundtrip(payload: dict):
    assert_that(
        Hs256("wandering-albatross-crossing-the-southern-ocean").decoded(
            Hs256("wandering-albatross-crossing-the-southern-ocean").encoded(payload),
            {},
        ),
        equal_to(payload),
        "HS256 must restore every payload it encoded",
    )


def test_restores_empty_payload():
    assert_that(
        Hs256("hollow-secret-stretched-past-thirty-two-bytes").decoded(
            Hs256("hollow-secret-stretched-past-thirty-two-bytes").encoded({}), {}
        ),
        equal_to({}),
        "HS256 must survive a payload with no claims at all",
    )


def test_restores_non_ascii_payload():
    assert_that(
        Hs256("κλειδί-με-αρκετούς-χαρακτήρες-για-ασφάλεια").decoded(
            Hs256("κλειδί-με-αρκετούς-χαρακτήρες-για-ασφάλεια").encoded(
                {"name": "Дракон 🐉"}
            ),
            {},
        ),
        equal_to({"name": "Дракон 🐉"}),
        "HS256 must keep non-ASCII claim values intact",
    )


def test_restores_huge_payload():
    assert_that(
        Hs256("giant-secret-stretching-far-beyond-thirty-two-bytes").decoded(
            Hs256("giant-secret-stretching-far-beyond-thirty-two-bytes").encoded(
                {"blob": "z" * 65536}
            ),
            {},
        ),
        equal_to({"blob": "z" * 65536}),
        "HS256 must carry a very large claim value",
    )


def test_rejects_foreign_secret():
    assert_that(
        calling(Hs256("first-secret-of-sufficient-length-for-hmac").decoded).with_args(
            Hs256("second-secret-of-sufficient-length-for-hmac").encoded(
                {"sub": "314"}
            ),
            {},
        ),
        raises(Exception),
        "HS256 must refuse a token signed with another secret",
    )


def test_rejects_malformed_raw_string():
    assert_that(
        calling(
            Hs256("tidy-secret-long-enough-to-satisfy-the-hmac-rule").decoded
        ).with_args("this.is.rubbish", {}),
        raises(Exception),
        "HS256 must refuse a string that is not a token",
    )


def test_restores_payload_signed_with_rsa():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    assert_that(
        Rs256(pem, pub).decoded(Rs256(pem, pub).encoded({"sub": "1789"}), {}),
        equal_to({"sub": "1789"}),
        "RS256 must restore the payload it signed with the private key",
    )


def test_restores_payload_signed_with_elliptic_curve():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    assert_that(
        Es256(pem, pub).decoded(Es256(pem, pub).encoded({"sub": "1066"}), {}),
        equal_to({"sub": "1066"}),
        "ES256 must restore the payload it signed with the private key",
    )


def test_restores_payload_meant_for_its_audience():
    assert_that(
        AudienceSignature(
            Hs256("billing-secret-stretching-beyond-thirty-two-bytes"), "billing"
        ).decoded(
            Hs256("billing-secret-stretching-beyond-thirty-two-bytes").encoded(
                {"sub": "2718", "aud": "billing"}
            ),
            {},
        ),
        equal_to({"sub": "2718", "aud": "billing"}),
        "Audience signature must restore a payload addressed to its audience",
    )


def test_restores_payload_listing_its_audience_among_others():
    assert_that(
        AudienceSignature(
            Hs256("crowd-secret-stretching-beyond-thirty-two-bytes!"), "search"
        ).decoded(
            Hs256("crowd-secret-stretching-beyond-thirty-two-bytes!").encoded(
                {"sub": "1618", "aud": ["mail", "search", "calendar"]}
            ),
            {},
        ),
        has_entry("aud", ["mail", "search", "calendar"]),
        "Audience signature must accept a payload that lists its audience",
    )


def test_rejects_payload_meant_for_another_audience():
    assert_that(
        calling(
            AudienceSignature(
                Hs256("stranger-secret-stretching-beyond-thirty-two-bytes"),
                "warehouse",
            ).decoded
        ).with_args(
            Hs256("stranger-secret-stretching-beyond-thirty-two-bytes").encoded(
                {"sub": "1414", "aud": "storefront"}
            ),
            {},
        ),
        raises(Exception, "Audience"),
        "Audience signature must refuse a payload addressed to someone else",
    )


def test_rejects_payload_without_audience_claim():
    assert_that(
        calling(
            AudienceSignature(
                Hs256("nameless-secret-stretching-beyond-thirty-two-bytes"),
                "gateway",
            ).decoded
        ).with_args(
            Hs256("nameless-secret-stretching-beyond-thirty-two-bytes").encoded(
                {"sub": "3141"}
            ),
            {},
        ),
        raises(Exception, "aud"),
        "Audience signature must refuse a payload that names no audience",
    )


def test_rejects_forged_token_before_looking_at_audience():
    assert_that(
        calling(
            AudienceSignature(
                Hs256("genuine-secret-stretching-beyond-thirty-two-bytes"),
                "vault",
            ).decoded
        ).with_args(
            Hs256("forged-secret-stretching-beyond-thirty-two-bytes!").encoded(
                {"sub": "1729", "aud": "vault"}
            ),
            {},
        ),
        raises(Exception, "Signature"),
        "Audience signature must still refuse a token signed with another secret",
    )


def test_forwards_decode_options_to_origin():
    assert_that(
        AudienceSignature(
            Hs256("bygone-secret-stretching-beyond-thirty-two-bytes"), "archive"
        ).decoded(
            Hs256("bygone-secret-stretching-beyond-thirty-two-bytes").encoded(
                {"aud": "archive", "exp": 1}
            ),
            {"verify_exp": False},
        ),
        has_entry("exp", 1),
        "Audience signature must pass the decode options on to its origin",
    )


def test_encodes_through_origin():
    assert_that(
        AudienceSignature(
            FakeSignature("aud.ien.ce", {"sub": "6174"}), "printing-press"
        ).encoded({"sub": "6174"}),
        equal_to("aud.ien.ce"),
        "Audience signature must leave encoding to its origin",
    )
