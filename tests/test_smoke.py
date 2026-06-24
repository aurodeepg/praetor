"""M0 smoke test: the package imports and is installed. Real tests arrive with M1."""

import praetor


def test_package_imports_and_has_version():
    assert isinstance(praetor.__version__, str)
    assert praetor.__version__
