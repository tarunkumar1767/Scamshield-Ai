import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import analyzer
from app.config import Settings
from app.main import app, settings


class SettingsAndRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_timeout_setting_has_default_environment_and_bounds(self):
        with patch.dict(os.environ, clear=True):
            self.assertEqual(Settings(_env_file=None).ai_request_timeout_seconds, 60)
            os.environ["AI_REQUEST_TIMEOUT_SECONDS"] = "45"
            self.assertEqual(Settings(_env_file=None).ai_request_timeout_seconds, 45)
            os.environ["AI_REQUEST_TIMEOUT_SECONDS"] = "301"
            with self.assertRaises(Exception):
                Settings(_env_file=None)
            os.environ.pop("AI_REQUEST_TIMEOUT_SECONDS", None)

    def test_health_and_all_scanner_routes_are_registered(self):
        routes = {route.path: route.methods for route in app.routes if hasattr(route, "methods")}
        self.assertIn("GET", routes["/api/health"])
        self.assertIn("POST", routes["/api/analyze/message"])
        self.assertIn("POST", routes["/api/analyze/image"])
        self.assertIn("POST", routes["/api/analyze/url"])
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertNotIn("api_key", response.json())

    def test_demo_mode_message_endpoint_returns_complete_analysis(self):
        with patch.object(settings, "demo_mode", True):
            with patch.object(settings, "ai_api_key", ""):
                response = self.client.post("/api/analyze/message", json={"message": "Hello, how are you?"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["analysis_source"], "demo")
        self.assertTrue(body["demo_mode"])
        self.assertIn(body["risk_level"], {"SAFE", "LOW RISK", "MEDIUM RISK", "HIGH RISK", "CRITICAL RISK"})
        self.assertIn("risk_score", body)
        self.assertIn("category", body)
        self.assertIn("red_flags", body)
        self.assertIn("evidence", body)
        self.assertIn("recommended_actions", body)
        self.assertIn("safety_tips", body)

    def test_image_endpoint_sends_ocr_text_through_message_analysis(self):
        with patch.object(settings, "demo_mode", True):
            response = self.client.post(
                "/api/analyze/image",
                json={"extracted_text": "Urgent: your account is suspended, send your OTP"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["analysis_source"], "demo")
        self.assertEqual(response.json()["risk_level"], "HIGH RISK")

    def test_url_endpoint_remains_heuristic_and_does_not_fetch_url(self):
        with patch.object(settings, "demo_mode", True):
            response = self.client.post("/api/analyze/url", json={"url": "http://127.0.0.1/login?verify=1"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["assessment_type"], "heuristic")
        self.assertEqual(body["domain"], "127.0.0.1")
        self.assertIn("findings", body)
        self.assertIn("risk_score", body)

    def test_invalid_message_is_rejected_as_request_validation_not_provider_outage(self):
        response = self.client.post("/api/analyze/message", json={"message": "   "})
        self.assertEqual(response.status_code, 422)

    def test_cors_preflight_allows_deployed_frontend(self):
        response = self.client.options(
            "/api/analyze/message",
            headers={
                "Origin": "https://scamshield-ai-j7gz.vercel.app",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("access-control-allow-origin"),
            "https://scamshield-ai-j7gz.vercel.app",
        )
        self.assertIn("POST", response.headers.get("access-control-allow-methods", ""))
        self.assertNotEqual(response.headers.get("access-control-allow-origin"), "*")

    def test_provider_failure_at_route_returns_analysis_not_http_503(self):
        fallback = {
            "risk_level": "SAFE",
            "risk_score": 5,
            "category": "Other",
            "summary": "Deterministic fallback.",
            "red_flags": [],
            "evidence": [],
            "recommended_actions": ["Verify unexpected requests independently."],
            "safety_tips": ["A scan is not a guarantee."],
            "demo_mode": False,
            "analysis_source": "fallback",
            "fallback_reason": "AI_PROVIDER_ERROR",
        }
        with patch.object(settings, "demo_mode", False):
            with patch("app.main.analyze_with_ai", return_value=fallback):
                response = self.client.post("/api/analyze/message", json={"message": "Hello"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["analysis_source"], "fallback")

    def test_message_route_to_gemini_sdk_response_end_to_end(self):
        output = {
            "risk_level": "HIGH RISK",
            "risk_score": 84,
            "category": "Account Takeover",
            "summary": "The message requests a one-time verification code.",
            "red_flags": ["Requests an OTP"],
            "evidence": [{"quote": "send your OTP", "reason": "Requests a one-time code."}],
            "recommended_actions": ["Do not share the code."],
            "safety_tips": ["Verify through the official app."],
        }
        sdk_client = SimpleNamespace(
            interactions=SimpleNamespace(
                create=lambda **_kwargs: SimpleNamespace(output_text=json.dumps(output)),
            ),
            close=lambda: None,
        )
        with patch.object(settings, "demo_mode", False):
            with patch.object(settings, "ai_api_key", "test-key"):
                with patch.object(settings, "ai_model", "gemini-3.8-flash"):
                    with patch.object(
                        settings,
                        "ai_api_base_url",
                        "https://generativelanguage.googleapis.com/v1beta/openai/",
                    ):
                        with patch.object(analyzer.genai, "Client", return_value=sdk_client):
                            response = self.client.post(
                                "/api/analyze/message",
                                json={"message": "The bank asks me to send my OTP"},
                            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["analysis_source"], "ai")
        self.assertEqual(response.json()["risk_level"], "HIGH RISK")
        self.assertEqual(response.json()["risk_score"], 84)


if __name__ == "__main__":
    unittest.main()
