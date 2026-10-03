import os
import tempfile
import unittest
import shutil

from audit import audit_hash, save_report, authenticate, create_demo_admin


class EnterpriseTests(unittest.TestCase):

    def test_argon2_policy(self):
        r = audit_hash('a' * 64, 'sha256')
        self.assertGreaterEqual(r['risk_score'], 35)

    def test_history_and_login(self):
        d = tempfile.mkdtemp()
        try:
            db = os.path.join(d, 'a.db')
            create_demo_admin(db)
            user = authenticate('admin', 'HydraAudit!2026', db)
            self.assertIsNotNone(user)
            self.assertEqual(user['role'], 'admin')
            r = audit_hash('a' * 32, 'md5')
            json_path = os.path.join(d, 'r.json')
            csv_path = os.path.join(d, 'r.csv')
            save_report(r, json_path, csv_path, db)
            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(csv_path))
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
