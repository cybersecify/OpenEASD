"""Unit tests for apps/core/ai/client.py — the Cloudflare Workers AI client.

The client must be fail-graceful (never raises), audit every logical call with
metadata only, validate structured output with one corrective retry, and
enforce the per-scan call budget.
"""

import pytest
from unittest.mock import MagicMock, patch

from apps.core.ai import client
from apps.core.ai.models import AIInvocation
from apps.core.ai.schemas import SummaryOut


def _session(domain="example.com"):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain=domain, scan_type="full")


def _resp(status=200, json_body=None, headers=None):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    if json_body is None:
        r.json.side_effect = ValueError("no json")
    else:
        r.json.return_value = json_body
    return r


def _envelope(response, usage=None):
    result = {"response": response}
    if usage is not None:
        result["usage"] = usage
    return {"success": True, "result": result, "errors": [], "messages": []}


_MESSAGES = [{"role": "user", "content": "summarize"}]


@pytest.fixture
def configured(settings):
    settings.CLOUDFLARE_ACCOUNT_ID = "acct123"
    settings.CLOUDFLARE_API_TOKEN = "tok456"
    settings.CLOUDFLARE_AI_MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
    settings.CLOUDFLARE_AI_MAX_CALLS_PER_SCAN = 10
    return settings


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestIsConfigured:
    def test_both_set(self, configured):
        assert client.is_configured() is True

    def test_missing_token(self, settings):
        settings.CLOUDFLARE_ACCOUNT_ID = "acct"
        settings.CLOUDFLARE_API_TOKEN = ""
        assert client.is_configured() is False

    def test_missing_account(self, settings):
        settings.CLOUDFLARE_ACCOUNT_ID = ""
        settings.CLOUDFLARE_API_TOKEN = "tok"
        assert client.is_configured() is False

    def test_db_saved_credentials_suffice_without_env(self, settings):
        from apps.core.ai.models import AISettings
        settings.CLOUDFLARE_ACCOUNT_ID = ""
        settings.CLOUDFLARE_API_TOKEN = ""
        cfg = AISettings.get()
        cfg.cloudflare_account_id = "db-acct"
        cfg.cloudflare_api_token = "db-tok"
        cfg.save()
        assert client.is_configured() is True
        assert client.account_id() == "db-acct"
        assert client.api_token() == "db-tok"

    def test_db_wins_over_env(self, configured):
        from apps.core.ai.models import AISettings
        cfg = AISettings.get()
        cfg.cloudflare_account_id = "db-acct"
        cfg.cloudflare_api_token = "db-tok"
        cfg.save()
        assert client.account_id() == "db-acct"  # env "acct456" loses
        assert client.api_token() == "db-tok"

    def test_cleared_db_falls_back_to_env(self, configured):
        from apps.core.ai.models import AISettings
        cfg = AISettings.get()
        cfg.cloudflare_account_id = "   "  # whitespace = effectively cleared
        cfg.save()
        assert client.account_id() == "acct123"


@pytest.mark.django_db
class TestResolveModel:
    def test_env_default(self, configured):
        assert client.resolve_model() == "@cf/meta/llama-3.3-70b-instruct-fp8-fast"

    def test_db_override_wins(self, configured):
        from apps.core.ai.models import AISettings
        cfg = AISettings.get()
        cfg.model_override = "@cf/qwen/qwen2.5-coder-32b-instruct"
        cfg.save()
        assert client.resolve_model() == "@cf/qwen/qwen2.5-coder-32b-instruct"


# ---------------------------------------------------------------------------
# chat_json — happy paths
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestChatJsonSuccess:
    def test_unconfigured_returns_none_without_http(self, settings):
        settings.CLOUDFLARE_ACCOUNT_ID = ""
        settings.CLOUDFLARE_API_TOKEN = ""
        with patch("apps.core.ai.client.requests.post") as post:
            assert client.chat_json(_MESSAGES, SummaryOut, purpose="test") is None
        post.assert_not_called()
        assert AIInvocation.objects.count() == 0

    def test_dict_response_validated_and_audited(self, configured):
        sess = _session()
        body = _envelope({"text": "all clear"}, usage={"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120})
        with patch("apps.core.ai.client.requests.post", return_value=_resp(json_body=body)) as post:
            out = client.chat_json(_MESSAGES, SummaryOut, purpose="alert_summary",
                                   session=sess, finding_ids=[1, 2])
        assert out == {"text": "all clear"}
        url = post.call_args[0][0]
        assert "acct123" in url and "@cf/meta/llama-3.3-70b-instruct-fp8-fast" in url
        assert post.call_args[1]["headers"]["Authorization"] == "Bearer tok456"
        sent = post.call_args[1]["json"]
        assert sent["response_format"]["type"] == "json_schema"
        row = AIInvocation.objects.get()
        assert row.status == "ok"
        assert row.purpose == "alert_summary"
        assert row.prompt_tokens == 100 and row.total_tokens == 120
        assert row.finding_ids == [1, 2]
        assert row.session_uuid == sess.uuid

    def test_string_response_parsed(self, configured):
        body = _envelope('{"text": "ok"}')
        with patch("apps.core.ai.client.requests.post", return_value=_resp(json_body=body)):
            out = client.chat_json(_MESSAGES, SummaryOut, purpose="test")
        assert out == {"text": "ok"}
        assert AIInvocation.objects.get().session is None  # test calls have no session


# ---------------------------------------------------------------------------
# chat_json — failure modes (never raises, always audited)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestChatJsonFailures:
    def test_timeout(self, configured):
        import requests as requests_lib
        with patch("apps.core.ai.client.requests.post", side_effect=requests_lib.Timeout):
            assert client.chat_json(_MESSAGES, SummaryOut, purpose="triage", session=_session()) is None
        assert AIInvocation.objects.get().status == "timeout"

    def test_connection_error(self, configured):
        import requests as requests_lib
        with patch("apps.core.ai.client.requests.post", side_effect=requests_lib.ConnectionError):
            assert client.chat_json(_MESSAGES, SummaryOut, purpose="triage") is None
        assert AIInvocation.objects.get().status == "http_error"

    def test_5xx_retries_then_fails(self, configured):
        with patch("apps.core.ai.client.requests.post", return_value=_resp(status=500, json_body={})) as post, \
             patch("apps.core.ai.client.time.sleep") as slept:
            assert client.chat_json(_MESSAGES, SummaryOut, purpose="triage") is None
        assert post.call_count == 2  # initial + one retry
        slept.assert_called_once()
        assert AIInvocation.objects.get().status == "http_error"

    def test_429_backoff_capped_then_success(self, configured):
        ok = _resp(json_body=_envelope({"text": "ok"}))
        limited = _resp(status=429, json_body={}, headers={"Retry-After": "9999"})
        with patch("apps.core.ai.client.requests.post", side_effect=[limited, ok]), \
             patch("apps.core.ai.client.time.sleep") as slept:
            out = client.chat_json(_MESSAGES, SummaryOut, purpose="triage")
        assert out == {"text": "ok"}
        assert slept.call_args[0][0] <= client._MAX_BACKOFF

    def test_429_exhausted(self, configured):
        limited = _resp(status=429, json_body={}, headers={})
        with patch("apps.core.ai.client.requests.post", return_value=limited), \
             patch("apps.core.ai.client.time.sleep"):
            assert client.chat_json(_MESSAGES, SummaryOut, purpose="triage") is None
        assert AIInvocation.objects.get().status == "rate_limited"

    def test_non_json_body(self, configured):
        with patch("apps.core.ai.client.requests.post", return_value=_resp(json_body=None)):
            assert client.chat_json(_MESSAGES, SummaryOut, purpose="triage") is None
        assert AIInvocation.objects.get().status == "bad_json"

    def test_http_4xx(self, configured):
        with patch("apps.core.ai.client.requests.post", return_value=_resp(status=403, json_body={})):
            assert client.chat_json(_MESSAGES, SummaryOut, purpose="triage") is None
        assert AIInvocation.objects.get().status == "http_error"


# ---------------------------------------------------------------------------
# chat_json — schema validation retry
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestSchemaRetry:
    def test_mismatch_then_valid(self, configured):
        bad = _resp(json_body=_envelope({"wrong_field": 1}))
        good = _resp(json_body=_envelope({"text": "fixed"}))
        with patch("apps.core.ai.client.requests.post", side_effect=[bad, good]) as post:
            out = client.chat_json(_MESSAGES, SummaryOut, purpose="triage")
        assert out == {"text": "fixed"}
        # Corrective message appended on the retry call.
        retry_messages = post.call_args_list[1][1]["json"]["messages"]
        assert len(retry_messages) == len(_MESSAGES) + 1
        assert "did not match the required JSON schema" in retry_messages[-1]["content"]
        statuses = list(AIInvocation.objects.order_by("id").values_list("status", flat=True))
        assert statuses == ["schema_mismatch", "ok"]

    def test_mismatch_twice_gives_up(self, configured):
        bad = _resp(json_body=_envelope({"wrong_field": 1}))
        with patch("apps.core.ai.client.requests.post", return_value=bad) as post:
            assert client.chat_json(_MESSAGES, SummaryOut, purpose="triage") is None
        assert post.call_count == 2
        statuses = list(AIInvocation.objects.values_list("status", flat=True))
        assert statuses == ["schema_mismatch", "schema_mismatch"]

    def test_api_level_failure_envelope(self, configured):
        body = {"success": False, "errors": [{"code": 10000, "message": "auth error"}]}
        with patch("apps.core.ai.client.requests.post", return_value=_resp(json_body=body)) as post:
            assert client.chat_json(_MESSAGES, SummaryOut, purpose="triage") is None
        assert post.call_count == 2  # treated as unusable output -> one corrective retry


# ---------------------------------------------------------------------------
# Per-scan call budget
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCallBudget:
    def test_budget_exhausted_refuses_without_http(self, configured):
        configured.CLOUDFLARE_AI_MAX_CALLS_PER_SCAN = 2
        sess = _session()
        for _ in range(2):
            AIInvocation.objects.create(session=sess, session_uuid=sess.uuid,
                                        purpose="triage", model="m", status="ok")
        with patch("apps.core.ai.client.requests.post") as post:
            assert client.chat_json(_MESSAGES, SummaryOut, purpose="triage", session=sess) is None
        post.assert_not_called()
        assert AIInvocation.objects.count() == 2  # no new row for a refused call

    def test_budget_counts_only_this_session(self, configured):
        configured.CLOUDFLARE_AI_MAX_CALLS_PER_SCAN = 1
        other = _session(domain="other.example.com")
        AIInvocation.objects.create(session=other, session_uuid=other.uuid,
                                    purpose="triage", model="m", status="ok")
        sess = _session()
        body = _envelope({"text": "ok"})
        with patch("apps.core.ai.client.requests.post", return_value=_resp(json_body=body)):
            assert client.chat_json(_MESSAGES, SummaryOut, purpose="triage", session=sess) is not None
