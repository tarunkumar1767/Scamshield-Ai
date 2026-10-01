import io
import json
import logging
import unittest
from contextlib import ExitStack
from unittest.mock import call
from unittest.mock import patch
from urllib.error import HTTPError

from app import analyzer


class FakeResponse:
    status = 200

    def __init__(self, body: dict):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


class GeminiRequestTests(unittest.TestCase):
    def setUp(self):
        self.settings_patches = ExitStack()
        self.settings_patches.enter_context(patch.object(analyzer.settings, "ai_api_key", "test-provider-key"))
        self.settings_patches.enter_context(patch.object(analyzer.settings, "ai_model", "gemini-3.8-flash"))
        self.settings_patches.enter_context(patch.object(analyzer.settings, "ai_request_timeout_seconds", 60))
        self.settings_patches.enter_context(patch.object(
            analyzer.settings,
            "ai_api_base_url",
            "https://generativelanguage.googleapis.com/v1beta/openai/",
        ))

    def tearDown(self):
        self.settings_patches.close()

    @staticmethod
    def valid_analysis():
        return {
            "risk_level": "high",
            "risk_score": 84,
            "category": "Credential theft",
            "summary": "The message pressures the recipient to disclose an account code.",
            "red_flags": ["Requests a verification code"],
            "evidence": [{"quote": "send your OTP", "reason": "Requests a one-time code."}],
            "recommended_actions": ["Do not reply."],
            "safety_tips": ["Contact the provider through its official app."],
        }

    def test_gemini_success_uses_supported_request_and_validates_response(self):
        result_content = json.dumps(self.valid_analysis())
        response = FakeResponse({"choices": [{"message": {"content": [{"type": "text", "text": result_content}]}}]})
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["payload"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return response

        with patch.object(analyzer, "urlopen", side_effect=fake_urlopen):
            result = analyzer.analyze_with_ai("Please send your OTP now")

        self.assertEqual(captured["url"], "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions")
        self.assertEqual(captured["payload"]["model"], "gemini-3.8-flash")
        self.assertEqual(captured["timeout"], 60)
        self.assertNotIn("temperature", captured["payload"])
        self.assertNotIn("response_format", captured["payload"])
        prompt = captured["payload"]["messages"][0]["content"]
        self.assertIn('"risk_score"', prompt)
        self.assertIn("required", prompt)
        self.assertEqual(result.risk_level, "high")
        self.assertEqual(result.analysis_source, "ai")
        self.assertFalse(result.demo_mode)

    def test_gemini_rejected_configuration_is_mapped_and_logged_safely(self):
        private_message = "Unsupported temperature field; do not print this provider detail"
        error_body = json.dumps({
            "error": {"code": "INVALID_ARGUMENT", "type": "invalid_argument", "message": private_message}
        }).encode("utf-8")
        provider_error = HTTPError("https://provider.invalid", 400, "Bad Request", None, io.BytesIO(error_body))

        with self.assertLogs(analyzer.logger, level=logging.WARNING) as logs:
            with patch.object(analyzer, "urlopen", side_effect=provider_error):
                with self.assertRaises(analyzer.AnalysisProviderError) as raised:
                    analyzer.analyze_with_ai("private user message")

        self.assertEqual(raised.exception.code, "AI_PROVIDER_ERROR")
        diagnostic = "\n".join(logs.output)
        self.assertIn("status=400", diagnostic)
        self.assertIn("error_type=invalid_argument", diagnostic)
        self.assertNotIn(private_message, diagnostic)
        self.assertNotIn("test-provider-key", diagnostic)
        self.assertNotIn("private user message", diagnostic)
        self.assertNotIn("Authorization", diagnostic)

    def test_invalid_gemini_content_is_rejected_instead_of_reported_as_ai_success(self):
        response = FakeResponse({"choices": [{"message": {"content": '{"risk_level":"critical"}'}}]})
        with patch.object(analyzer, "urlopen", return_value=response):
            with self.assertRaises(analyzer.AnalysisProviderError) as raised:
                analyzer.analyze_with_ai("Harmless content")

        self.assertEqual(raised.exception.code, "AI_PROVIDER_ERROR")

    def test_rate_limit_quota_uses_existing_fallback(self):
        error_body = json.dumps({
            "error": {"code": "RESOURCE_EXHAUSTED", "type": "resource_exhausted", "message": "Quota exceeded"}
        }).encode("utf-8")
        provider_error = HTTPError("https://provider.invalid", 429, "Too Many Requests", None, io.BytesIO(error_body))

        with patch.object(analyzer, "urlopen", side_effect=provider_error):
            result = analyzer.analyze_with_ai("Urgent: send your OTP immediately")

        self.assertEqual(result.analysis_source, "fallback")
        self.assertEqual(result.fallback_reason, "AI_QUOTA_EXCEEDED")
        self.assertFalse(result.demo_mode)
        self.assertEqual(result.risk_level, "high")

    def test_timeout_uses_configured_value_and_preserves_fallback(self):
        with patch.object(analyzer, "urlopen", side_effect=TimeoutError()) as provider:
            result = analyzer.analyze_with_ai("Urgent: send your OTP immediately")

        self.assertEqual(provider.call_count, 1)
        self.assertEqual(provider.call_args.kwargs["timeout"], 60)
        self.assertEqual(result.analysis_source, "fallback")
        self.assertEqual(result.fallback_reason, "AI_TIMEOUT")
        self.assertFalse(result.demo_mode)

    def test_rate_limit_retry_count_and_backoff_are_preserved(self):
        rate_limit_body = json.dumps({
            "error": {"type": "rate_limit_error", "message": "Temporary rate limit"}
        }).encode("utf-8")
        rate_limits = [
            HTTPError("https://provider.invalid", 429, "Too Many Requests", None, io.BytesIO(rate_limit_body))
            for _ in range(2)
        ]
        response = FakeResponse({"choices": [{"message": {"content": json.dumps(self.valid_analysis())}}]})

        with patch.object(analyzer, "urlopen", side_effect=[*rate_limits, response]) as provider:
            with patch.object(analyzer.time, "sleep") as sleep:
                result = analyzer.analyze_with_ai("Harmless message")

        self.assertEqual(provider.call_count, analyzer.MAX_RATE_LIMIT_RETRIES + 1)
        self.assertEqual([entry.kwargs["timeout"] for entry in provider.call_args_list], [60, 60, 60])
        self.assertEqual(sleep.call_args_list, [call(0.25), call(0.5)])
        self.assertEqual(result.analysis_source, "ai")


if __name__ == "__main__":
    unittest.main()
