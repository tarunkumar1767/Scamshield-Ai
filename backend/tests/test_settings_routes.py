import os
import unittest
from unittest.mock import patch

from app.config import Settings
from app.main import MessageAnalysisRequest, analyze_message, app, health, settings


class SettingsAndRouteTests(unittest.TestCase):
    def test_timeout_setting_has_default_and_reads_environment_variable(self):
        with patch.dict(os.environ):
            os.environ.pop("AI_REQUEST_TIMEOUT_SECONDS", None)
            self.assertEqual(Settings(_env_file=None).ai_request_timeout_seconds, 60)
            os.environ["AI_REQUEST_TIMEOUT_SECONDS"] = "45"
            self.assertEqual(Settings(_env_file=None).ai_request_timeout_seconds, 45)

    def test_health_and_scanner_routes_are_registered(self):
        routes = {route.path: route.methods for route in app.routes if hasattr(route, "methods")}
        self.assertIn("GET", routes["/api/health"])
        self.assertIn("POST", routes["/api/analyze/message"])
        self.assertIn("POST", routes["/api/analyze/image"])
        self.assertIn("POST", routes["/api/analyze/url"])
        self.assertEqual(health()["status"], "ok")

    def test_message_endpoint_runs_through_demo_analysis(self):
        with patch.object(settings, "demo_mode", True):
            result = analyze_message(MessageAnalysisRequest(message="Hello, how are you?"))

        self.assertEqual(result.analysis_source, "demo")
        self.assertTrue(result.demo_mode)


if __name__ == "__main__":
    unittest.main()
