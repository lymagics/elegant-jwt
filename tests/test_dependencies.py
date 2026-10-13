from importlib.metadata import metadata, requires

import pytest
from hamcrest import assert_that, equal_to, has_item, matches_regexp


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


def test_declares_python_floor_supported_by_dev_dependencies():
    assert_that(
        metadata("elegant-jwt")["Requires-Python"],
        equal_to(">=3.11"),
        "Package must require Python 3.11+, since hypothesis dropped 3.10",
    )
