from importlib.metadata import requires

import pytest
from hamcrest import assert_that, has_item, matches_regexp


@pytest.mark.parametrize(
    "name",
    ["pyjwt\\[crypto\\]", "plum-dispatch"],
)
def test_declares_lower_bound_for_runtime_dependency(name: str):
    assert_that(
        requires("elegant-jwt"),
        has_item(matches_regexp(f"^{name}.*>=")),
        f"Package metadata must declare {name} with a lower bound, not a pin",
    )
