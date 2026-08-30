import time

from hamcrest import assert_that, close_to

from elegant_jwt import SystemClock


def test_tells_current_unix_moment():
    assert_that(
        SystemClock().moment(),
        close_to(time.time(), 5.0),
        "System clock must tell the current Unix time",
    )
