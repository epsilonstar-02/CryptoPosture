"""
tests/test_auth_and_db.py
Comprehensive test suite for the Database Persistence and Authentication (RBAC) system:
1. Database initialization and model integrity
2. User registration and role bootstrapping (first user = admin, next = analyst)
3. Password hashing and verification
4. JWT token generation, expiration, and decoding
5. Authentication flows (JSON login and OAuth2 form login)
6. Role-Based Access Control (Admin vs Analyst permissions)
7. Audit log generation and querying
8. Analysis persistence on /api/analyze and instant retrieval via /api/history
9. Analysis deletion and permission guards
"""

from __future__ import annotations

import io
import os
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.app import app
from core.auth import create_access_token, hash_password, verify_password
from core.db import Base, get_db
from core.db_models import AnalysisRecord, AuditLog, User
from generator.pcap_generator import generate_all, DEFAULT_OUTPUT_DIR

TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


class TestAuthAndDB(unittest.TestCase):
    """Test suite for authentication, authorization, database storage, and history."""

    @classmethod
    def setUpClass(cls):
        SAMPLE_DIR = Path(DEFAULT_OUTPUT_DIR)
        SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
        generate_all(SAMPLE_DIR)

        # Override get_db dependency to use clean in-memory database
        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()

    def setUp(self):
        # Fresh schema before each test run
        Base.metadata.drop_all(bind=test_engine)
        Base.metadata.create_all(bind=test_engine)

    # -----------------------------------------------------------------------
    # 1. Password & Hash Verification
    # -----------------------------------------------------------------------
    def test_password_hashing_and_verification(self):
        password = "SuperSecretPassword123!"
        hashed = hash_password(password)
        self.assertNotEqual(password, hashed)
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password("WrongPassword123!", hashed))

    # -----------------------------------------------------------------------
    # 2. Registration & First-User Admin Promotion
    # -----------------------------------------------------------------------
    def test_first_user_becomes_admin_second_becomes_analyst(self):
        # First user registration
        resp1 = self.client.post(
            "/api/auth/register",
            json={
                "username": "chief_analyst",
                "email": "chief@agency.gov",
                "password": "SecurePassword1!",
                "full_name": "Chief Forensics Officer",
            },
        )
        self.assertEqual(resp1.status_code, 200, resp1.text)
        data1 = resp1.json()
        self.assertEqual(data1["user"]["role"], "admin")
        self.assertIn("access_token", data1)

        # Second user registration
        resp2 = self.client.post(
            "/api/auth/register",
            json={
                "username": "junior_analyst",
                "email": "junior@agency.gov",
                "password": "SecurePassword2!",
                "full_name": "Junior Forensics Analyst",
            },
        )
        self.assertEqual(resp2.status_code, 200, resp2.text)
        data2 = resp2.json()
        self.assertEqual(data2["user"]["role"], "analyst")

    def test_registration_rejects_duplicate_username_and_email(self):
        self.client.post(
            "/api/auth/register",
            json={"username": "analyst1", "email": "a1@test.local", "password": "Password123!"},
        )
        # Duplicate username
        resp_dup_user = self.client.post(
            "/api/auth/register",
            json={"username": "analyst1", "email": "other@test.local", "password": "Password123!"},
        )
        self.assertEqual(resp_dup_user.status_code, 400)
        self.assertEqual(resp_dup_user.json()["detail"]["error_code"], "USERNAME_EXISTS")

        # Duplicate email
        resp_dup_email = self.client.post(
            "/api/auth/register",
            json={"username": "otheruser", "email": "a1@test.local", "password": "Password123!"},
        )
        self.assertEqual(resp_dup_email.status_code, 400)
        self.assertEqual(resp_dup_email.json()["detail"]["error_code"], "EMAIL_EXISTS")

    # -----------------------------------------------------------------------
    # 3. Login Flow (JSON & OAuth2 Form)
    # -----------------------------------------------------------------------
    def test_login_flow(self):
        self.client.post(
            "/api/auth/register",
            json={"username": "sarah_connor", "email": "sarah@sky.net", "password": "NoFate1984!"},
        )

        # Correct login
        login_resp = self.client.post(
            "/api/auth/login",
            json={"username": "sarah_connor", "password": "NoFate1984!"},
        )
        self.assertEqual(login_resp.status_code, 200)
        token = login_resp.json()["access_token"]
        self.assertTrue(len(token) > 20)

        # Incorrect password
        fail_resp = self.client.post(
            "/api/auth/login",
            json={"username": "sarah_connor", "password": "WrongPassword!"},
        )
        self.assertEqual(fail_resp.status_code, 401)
        self.assertEqual(fail_resp.json()["detail"]["error_code"], "INVALID_CREDENTIALS")

        # OAuth2 password form login
        oauth_resp = self.client.post(
            "/api/auth/token",
            data={"username": "sarah_connor", "password": "NoFate1984!"},
        )
        self.assertEqual(oauth_resp.status_code, 200)
        self.assertIn("access_token", oauth_resp.json())

    # -----------------------------------------------------------------------
    # 4. User Profile (/me) and RBAC Protections
    # -----------------------------------------------------------------------
    def test_user_me_and_rbac_guards(self):
        # Register Admin
        r1 = self.client.post(
            "/api/auth/register",
            json={"username": "admin_user", "email": "admin@sec.net", "password": "AdminPassword1!"},
        )
        admin_token = r1.json()["access_token"]

        # Register Regular Analyst
        r2 = self.client.post(
            "/api/auth/register",
            json={"username": "soc_analyst", "email": "soc@sec.net", "password": "AnalystPassword1!"},
        )
        analyst_token = r2.json()["access_token"]

        # /me check with analyst token
        me_resp = self.client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.json()["username"], "soc_analyst")
        self.assertEqual(me_resp.json()["role"], "analyst")

        # Admin route: /api/auth/users
        # Analyst should be denied (403)
        denied_resp = self.client.get(
            "/api/auth/users",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        self.assertEqual(denied_resp.status_code, 403)

        # Admin should succeed (200)
        ok_resp = self.client.get(
            "/api/auth/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(ok_resp.status_code, 200)
        users = ok_resp.json()
        self.assertEqual(len(users), 2)

    # -----------------------------------------------------------------------
    # 5. Analysis Persistence, History & Retrieval
    # -----------------------------------------------------------------------
    def test_analysis_persistence_and_history_retrieval(self):
        # Register an analyst
        reg = self.client.post(
            "/api/auth/register",
            json={"username": "forensic_bot", "email": "bot@forensics.local", "password": "BotPassword123!"},
        )
        token = reg.json()["access_token"]

        sample_pcap = Path(DEFAULT_OUTPUT_DIR) / "clean_implicit_tls.pcap"
        self.assertTrue(sample_pcap.exists())

        # Upload and analyze with auth token
        with open(sample_pcap, "rb") as f:
            analyze_resp = self.client.post(
                "/api/analyze?run_ml=false",
                files={"file": ("clean_implicit_tls.pcap", f, "application/vnd.tcpdump.pcap")},
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(analyze_resp.status_code, 200)
        res_data = analyze_resp.json()
        analysis_id = res_data["meta"]["analysis_id"]
        self.assertTrue(analysis_id.startswith("an_"))
        self.assertEqual(res_data["meta"]["analyst"], "forensic_bot")

        # Query /api/history
        hist_resp = self.client.get("/api/history")
        self.assertEqual(hist_resp.status_code, 200)
        hist_data = hist_resp.json()
        self.assertGreaterEqual(hist_data["total"], 1)
        found_item = next((item for item in hist_data["items"] if item["id"] == analysis_id), None)
        self.assertIsNotNone(found_item)
        self.assertEqual(found_item["filename"], "clean_implicit_tls.pcap")
        self.assertEqual(found_item["username"], "forensic_bot")

        # Query /api/history/{analysis_id} (retrieval without re-upload)
        cached_resp = self.client.get(f"/api/history/{analysis_id}")
        self.assertEqual(cached_resp.status_code, 200)
        self.assertEqual(cached_resp.headers.get("X-Cached-Analysis"), "true")
        cached_data = cached_resp.json()
        self.assertEqual(cached_data["meta"]["analysis_id"], analysis_id)
        self.assertEqual(cached_data["evidence"]["filename"], "clean_implicit_tls.pcap")

        # Delete history record
        del_resp = self.client.delete(
            f"/api/history/{analysis_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(del_resp.json()["deleted_id"], analysis_id)

        # Verify it is gone
        del_check = self.client.get(f"/api/history/{analysis_id}")
        self.assertEqual(del_check.status_code, 404)

    def test_sample_analysis_persists_to_history(self):
        """Verify that running analysis on a sample scenario automatically persists to history."""
        # 1. Trigger sample analysis via /api/samples/{name}/analyze
        sample_resp = self.client.get("/api/samples/clean_implicit_tls/analyze")
        self.assertEqual(sample_resp.status_code, 200)
        data = sample_resp.json()
        analysis_id = sample_resp.headers.get("x-analysis-id")
        self.assertIsNotNone(analysis_id)
        self.assertTrue(analysis_id.startswith("an_"))
        self.assertEqual(data["meta"]["analysis_id"], analysis_id)
        self.assertEqual(data["evidence"]["filename"], "clean_implicit_tls.pcap")

        # 2. Query /api/history to verify it appears
        hist_resp = self.client.get("/api/history")
        self.assertEqual(hist_resp.status_code, 200)
        hist_data = hist_resp.json()
        found = any(item["id"] == analysis_id for item in hist_data["items"])
        self.assertTrue(found, f"Analysis {analysis_id} should appear in /api/history")

        # 3. Retrieve stored analysis from history without re-processing
        cache_resp = self.client.get(f"/api/history/{analysis_id}")
        self.assertEqual(cache_resp.status_code, 200)
        self.assertEqual(cache_resp.headers.get("x-cached-analysis"), "true")
        self.assertEqual(cache_resp.json()["evidence"]["filename"], "clean_implicit_tls.pcap")

    # -----------------------------------------------------------------------
    # 6. Audit Trail Logging
    # -----------------------------------------------------------------------
    def test_audit_log_trail(self):
        # Register user (generates USER_REGISTER audit log)
        r = self.client.post(
            "/api/auth/register",
            json={"username": "auditor_admin", "email": "admin@audit.local", "password": "AuditAdmin123!"},
        )
        token = r.json()["access_token"]

        # Fetch audit logs
        logs_resp = self.client.get(
            "/api/auth/audit-logs",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(logs_resp.status_code, 200)
        logs_data = logs_resp.json()
        self.assertGreaterEqual(logs_data["total"], 1)
        actions = [log["action"] for log in logs_data["logs"]]
        self.assertIn("USER_REGISTER", actions)


if __name__ == "__main__":
    unittest.main()
