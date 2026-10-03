import sys, os, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from audit import audit_hash
class AuditTests(unittest.TestCase):
    def test_md5_risk(self):
        r=audit_hash('098f6bcd4621d373cade4e832627b4f6'); self.assertEqual(r['algorithm'],'md5'); self.assertEqual(r['risk_level'],'HIGH')
    def test_sha256_format(self):
        r=audit_hash('a'*64); self.assertEqual(r['algorithm'],'sha256'); self.assertTrue(r['valid_format'])
    def test_invalid(self):
        r=audit_hash('not-a-hash'); self.assertFalse(r['valid_format']); self.assertEqual(r['risk_level'],'INVALID')
if __name__=='__main__': unittest.main()
