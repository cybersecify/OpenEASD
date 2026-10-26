from apps.core.engine.workflows import registry as R


def test_get_tool_verifiers_returns_callables_for_declaring_tools():
    verifiers = R.get_tool_verifiers()
    assert isinstance(verifiers, dict)
    # web_checker declares a verifier (added in a later task); until then this
    # dict may be empty. The contract under test: every value is callable, and
    # every key is a known tool source.
    runners = R.get_tool_runners()
    for source, fn in verifiers.items():
        assert source in runners
        assert callable(fn)


def test_get_tool_verifiers_skips_tools_without_the_key():
    # subfinder has no verifier -> must not appear.
    assert "subfinder" not in R.get_tool_verifiers()
