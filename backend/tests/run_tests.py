import sys
import unittest
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.test_iam import (
    test_user_registration,
    test_user_login_success,
    test_admin_role_modification,
    test_audit_log_tracking
)
from tests.test_detection import (
    test_benign_event_no_alert,
    test_brute_force_detection,
    test_credential_spraying_detection,
    test_impossible_travel_detection
)
from tests.test_ml import (
    test_ml_benign_event_scoring,
    test_ml_high_risk_event_scoring,
    test_ml_boundary_conditions
)
from tests.test_assistant_and_reports import (
    test_copilot_mitre_mapping,
    test_pdf_report_binary_generation
)
from tests.conftest import TestingSessionLocal, Base, test_engine
from app.models.user import User, UserRole
from app.core.security import hash_password


class SentinelFullTestSuite(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=test_engine)
        self.session = TestingSessionLocal()

    def tearDown(self):
        self.session.close()
        Base.metadata.drop_all(bind=test_engine)

    def _create_user(self, username, role):
        u = User(username=username, email=f"{username}@sentinel.test", hashed_password=hash_password("AdminPass123!"), role=role, is_active=True)
        self.session.add(u)
        self.session.commit()
        self.session.refresh(u)
        return u

    def test_01_iam_registration(self):
        test_user_registration(self.session)

    def test_02_iam_login(self):
        admin = self._create_user("admin_test", UserRole.ADMIN.value)
        test_user_login_success(self.session, admin)

    def test_03_iam_role_modification(self):
        admin = self._create_user("admin_test", UserRole.ADMIN.value)
        viewer = self._create_user("viewer_test", UserRole.VIEWER.value)
        test_admin_role_modification(self.session, admin, viewer)

    def test_04_iam_audit_logs(self):
        admin = self._create_user("admin_test", UserRole.ADMIN.value)
        test_audit_log_tracking(self.session, admin)

    def test_05_detection_benign(self):
        test_benign_event_no_alert(self.session)

    def test_06_detection_brute_force(self):
        test_brute_force_detection(self.session)

    def test_07_detection_ip_spray(self):
        test_credential_spraying_detection(self.session)

    def test_08_detection_impossible_travel(self):
        test_impossible_travel_detection(self.session)

    def test_09_ml_benign_scoring(self):
        test_ml_benign_event_scoring()

    def test_10_ml_high_risk_scoring(self):
        test_ml_high_risk_event_scoring()

    def test_11_ml_boundary(self):
        test_ml_boundary_conditions()

    def test_12_copilot_mitre(self):
        test_copilot_mitre_mapping()

    def test_13_pdf_report_generation(self):
        test_pdf_report_binary_generation()


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(SentinelFullTestSuite)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
