import json
import logging
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

from app import analyzer


class ProviderFailure(Exception):
    def __init__(self, status: int | None, status_name: str = "", message: str = ""):
        super().__init__(message or "private provider text must not be logged")
        self.code = status
        self.status = status_name
        self.message = message


class TimeoutException(Exception):
    pass


class TemporaryConnectionError(Exception):
    pass


class FakeGeminiClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False
        self.interactions = self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return SimpleNamespace(output_text=response)

    def close(self):
        self.closed = True


class FakeLegacyResponse:
    status = 200

    def __init__(self, body):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


class GeminiPipelineTests(unittest.TestCase):
    def setUp(self):
        self.settings_patches = [
            patch.object(analyzer.settings, "ai_api_key", "test-key"),
            patch.object(analyzer.settings, "ai_model", "gemini-3.8-flash"),
            patch.object(analyzer.settings, "ai_request_timeout_seconds", 60),
            patch.object(
                analyzer.settings,
                "ai_api_base_url",
                "https://generativelanguage.googleapis.com/v1beta/openai/",
            ),
        ]
        for patcher in self.settings_patches:
            patcher.start()
        self.addCleanup(lambda: [patcher.stop() for patcher in reversed(self.settings_patches)])

    @staticmethod
    def valid_analysis(score=84, risk_level=None):
        return {
            "risk_level": risk_level or analyzer.risk_level_for_score(score),
            "risk_score": score,
            "category": "Account Takeover",
            "summary": "The message asks for an account verification code.",
            "red_flags": ["Requests a verification code"],
            "evidence": [{"quote": "send your OTP", "reason": "Requests a one-time code."}],
            "recommended_actions": ["Do not reply or share the code."],
            "safety_tips": ["Contact the provider through its official app."],
        }

    def make_gemini_client(self, responses):
        client = FakeGeminiClient(responses)
        return client, patch.object(analyzer.genai, "Client", return_value=client)

    def test_gemini_success_uses_official_sdk_and_validates_structured_output(self):
        client, patched_sdk = self.make_gemini_client([json.dumps(self.valid_analysis())])
        with patched_sdk as constructor:
            result = analyzer.analyze_with_ai("Please send your OTP now")

        constructor.assert_called_once()
        self.assertEqual(constructor.call_args.kwargs["api_key"], "test-key")
        retry_options = constructor.call_args.kwargs["http_options"].retry_options
        self.assertEqual(retry_options.attempts, 1)
        request = client.calls[0]
        self.assertEqual(request["model"], "gemini-3.8-flash")
        self.assertEqual(request["timeout"], 60)
        self.assertFalse(request["store"])
        self.assertEqual(request["generation_config"], {"thinking_level": "low"})
        self.assertEqual(request["response_format"]["mime_type"], "application/json")
        self.assertEqual(request["response_format"]["schema"], analyzer.MESSAGE_OUTPUT_SCHEMA)
        self.assertNotIn("temperature", request)
        self.assertNotIn("top_p", request)
        self.assertNotIn("top_k", request)
        self.assertNotIn("candidate_count", request)
        self.assertIn("untrusted", request["input"].lower())
        self.assertEqual(result.risk_level, "HIGH RISK")
        self.assertEqual(result.analysis_source, "ai")
        self.assertFalse(result.demo_mode)
        self.assertTrue(client.closed)

    def test_non_gemini_provider_keeps_compatible_request_path(self):
        valid = self.valid_analysis(60)
        response = FakeLegacyResponse({"choices": [{"message": {"content": json.dumps(valid)}}]})
        with patch.object(analyzer.settings, "ai_api_base_url", "https://api.example.test/v1"):
            with patch.object(analyzer, "urlopen", return_value=response) as provider:
                result = analyzer.analyze_with_ai("A suspicious message")

        self.assertEqual(provider.call_count, 1)
        self.assertIn("/chat/completions", provider.call_args.args[0].full_url)
        self.assertEqual(result.analysis_source, "ai")
        self.assertEqual(result.risk_level, "MEDIUM RISK")

    def test_malformed_json_uses_fallback_not_ai_success(self):
        client, patched_sdk = self.make_gemini_client(["not-json"])
        with patched_sdk:
            result = analyzer.analyze_with_ai("Unrecognized content")

        self.assertEqual(result.analysis_source, "fallback")
        self.assertEqual(result.fallback_reason, "AI_PROVIDER_ERROR")
        self.assertFalse(result.demo_mode)
        analyzer.MessageAnalysis.model_validate(result.model_dump())

    def test_invalid_schema_and_risk_score_mismatch_use_fallback(self):
        malformed = self.valid_analysis(60, "HIGH RISK")
        malformed["extra_instruction"] = "not permitted"
        client, patched_sdk = self.make_gemini_client([json.dumps(malformed)])
        with patched_sdk:
            result = analyzer.analyze_with_ai("Unrecognized content")
        self.assertEqual(result.analysis_source, "fallback")
        self.assertEqual(result.fallback_reason, "AI_PROVIDER_ERROR")

        with self.assertRaises(Exception):
            analyzer.MessageAnalysis.model_validate_json(json.dumps(self.valid_analysis(101, "CRITICAL RISK")))
        with self.assertRaises(Exception):
            analyzer.MessageAnalysis.model_validate_json(json.dumps(self.valid_analysis(40, "HIGH RISK")))
        with self.assertRaises(Exception):
            analyzer.MessageAnalysis.model_validate_json(json.dumps(self.valid_analysis(True, "SAFE")))

    def test_risk_score_bands_are_exact(self):
        expected = [
            (0, "SAFE"), (20, "SAFE"), (21, "LOW RISK"), (50, "LOW RISK"),
            (51, "MEDIUM RISK"), (75, "MEDIUM RISK"), (76, "HIGH RISK"),
            (90, "HIGH RISK"), (91, "CRITICAL RISK"), (100, "CRITICAL RISK"),
        ]
        for score, label in expected:
            with self.subTest(score=score):
                self.assertEqual(analyzer.risk_level_for_score(score), label)
                result = analyzer.MessageAnalysis.model_validate(self.valid_analysis(score, label))
                self.assertEqual(result.risk_level, label)

    def test_transient_statuses_retry_then_return_ai_success(self):
        for status in (408, 429, 500, 502, 503, 504):
            with self.subTest(status=status):
                failure = ProviderFailure(status, message="temporary failure")
                client, patched_sdk = self.make_gemini_client([failure, json.dumps(self.valid_analysis())])
                with patched_sdk:
                    with patch.object(analyzer.time, "sleep") as sleep:
                        with patch.object(analyzer.random, "uniform", return_value=0.1):
                            result = analyzer.analyze_with_ai("A sample message")
                self.assertEqual(len(client.calls), 2)
                self.assertEqual(result.analysis_source, "ai")
                self.assertEqual(sleep.call_count, 1)

    def test_503_is_retried_a_bounded_number_of_times_then_falls_back(self):
        client, patched_sdk = self.make_gemini_client([
            ProviderFailure(503), ProviderFailure(503), ProviderFailure(503),
        ])
        with patched_sdk:
            with patch.object(analyzer.time, "sleep") as sleep:
                with patch.object(analyzer.random, "uniform", return_value=0.1):
                    result = analyzer.analyze_with_ai("Urgent: send your OTP immediately")

        self.assertEqual(len(client.calls), analyzer.MAX_PROVIDER_ATTEMPTS)
        self.assertEqual(sleep.call_count, analyzer.MAX_PROVIDER_ATTEMPTS - 1)
        self.assertEqual(result.analysis_source, "fallback")
        self.assertEqual(result.fallback_reason, "AI_PROVIDER_ERROR")
        analyzer.MessageAnalysis.model_validate(result.model_dump())

    def test_timeout_retries_then_uses_deterministic_fallback(self):
        client, patched_sdk = self.make_gemini_client([
            TimeoutException("private timeout"), TimeoutException("private timeout"),
            TimeoutException("private timeout"),
        ])
        with patched_sdk:
            with patch.object(analyzer.time, "sleep"):
                with patch.object(analyzer.random, "uniform", return_value=0.1):
                    result = analyzer.analyze_with_ai("Urgent: send your OTP immediately")

        self.assertEqual(len(client.calls), analyzer.MAX_PROVIDER_ATTEMPTS)
        self.assertEqual(result.analysis_source, "fallback")
        self.assertEqual(result.fallback_reason, "AI_TIMEOUT")
        self.assertEqual(result.risk_level, "MEDIUM RISK")

    def test_network_failure_retries_then_uses_fallback(self):
        client, patched_sdk = self.make_gemini_client([
            TemporaryConnectionError(), TemporaryConnectionError(), TemporaryConnectionError(),
        ])
        with patched_sdk:
            with patch.object(analyzer.time, "sleep"):
                with patch.object(analyzer.random, "uniform", return_value=0.1):
                    result = analyzer.analyze_with_ai("A sample message")

        self.assertEqual(len(client.calls), analyzer.MAX_PROVIDER_ATTEMPTS)
        self.assertEqual(result.analysis_source, "fallback")
        self.assertEqual(result.fallback_reason, "AI_NETWORK_ERROR")

    def test_quota_failure_falls_back_without_retry(self):
        quota_error = ProviderFailure(429, "RESOURCE_EXHAUSTED", "quota exceeded")
        client, patched_sdk = self.make_gemini_client([quota_error])
        with patched_sdk:
            result = analyzer.analyze_with_ai("Urgent: send your OTP immediately")

        self.assertEqual(len(client.calls), 1)
        self.assertEqual(result.analysis_source, "fallback")
        self.assertEqual(result.fallback_reason, "AI_QUOTA_EXCEEDED")

    def test_permanent_400_401_403_errors_fall_back_without_retry(self):
        expected = {400: "AI_PROVIDER_ERROR", 401: "AI_AUTH_FAILED", 403: "AI_AUTH_FAILED"}
        for status, code in expected.items():
            with self.subTest(status=status):
                client, patched_sdk = self.make_gemini_client([ProviderFailure(status)])
                with patched_sdk:
                    result = analyzer.analyze_with_ai("A sample message")
                self.assertEqual(len(client.calls), 1)
                self.assertEqual(result.analysis_source, "fallback")
                self.assertEqual(result.fallback_reason, code)

    def test_missing_api_key_returns_fallback(self):
        client, patched_sdk = self.make_gemini_client([])
        with patch.object(analyzer.settings, "ai_api_key", ""):
            with patched_sdk:
                result = analyzer.analyze_with_ai("A sample message")
        self.assertEqual(client.calls, [])
        self.assertEqual(result.analysis_source, "fallback")
        self.assertEqual(result.fallback_reason, "AI_CONFIGURATION_MISSING")

    def test_invalid_provider_url_returns_fallback_without_provider_call(self):
        client, patched_sdk = self.make_gemini_client([])
        with patch.object(analyzer.settings, "ai_api_base_url", "javascript:alert(1)"):
            with patched_sdk:
                result = analyzer.analyze_with_ai("A sample message")
        self.assertEqual(client.calls, [])
        self.assertEqual(result.analysis_source, "fallback")
        self.assertEqual(result.fallback_reason, "AI_PROVIDER_ERROR")

    def test_fallback_is_schema_valid_even_if_demo_analyzer_raises(self):
        with patch.object(analyzer, "analyze_demo", side_effect=RuntimeError("private data")):
            result = analyzer.analyze_fallback("Sensitive user message", "AI_PROVIDER_ERROR")
        self.assertEqual(result.analysis_source, "fallback")
        self.assertEqual(result.risk_level, "LOW RISK")
        self.assertEqual(result.risk_score, 21)
        analyzer.MessageAnalysis.model_validate(result.model_dump())

    def test_diagnostics_do_not_include_api_key_user_text_or_provider_message(self):
        private_provider_message = "provider error with private text"
        client, patched_sdk = self.make_gemini_client([ProviderFailure(503, message=private_provider_message)])
        with patched_sdk:
            with self.assertLogs(analyzer.logger, level=logging.WARNING) as logs:
                with patch.object(analyzer.time, "sleep"):
                    with patch.object(analyzer.random, "uniform", return_value=0.1):
                        result = analyzer.analyze_with_ai("user message with private content")
        diagnostic = "\n".join(logs.output)
        self.assertIn("provider=gemini", diagnostic)
        self.assertIn("status=503", diagnostic)
        self.assertIn("retry_attempt=1", diagnostic)
        self.assertNotIn("test-key", diagnostic)
        self.assertNotIn(private_provider_message, diagnostic)
        self.assertNotIn("user message with private content", diagnostic)
        self.assertNotIn("Authorization", diagnostic)
        self.assertEqual(result.analysis_source, "fallback")


if __name__ == "__main__":
    unittest.main()
