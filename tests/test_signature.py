from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from hamcrest import assert_that, calling, equal_to, raises
from hypothesis import given
from hypothesis import strategies as st

from elegant_jwt import Es256, Hs256, Rs256


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
