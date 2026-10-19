import unittest
import json
import io
from app import create_app
from models import db, User, SavedPassword, StrengthReport, AuditLog
from breach_checker import check_password_breach, check_breach_hibp_k_anonymity, check_breach_local
from recommendations_engine import SecurityRecommendationsEngine
from pdf_exporter import generate_pdf_report

class InternshipFeaturesTestCase(unittest.TestCase):
    def setUp(self):
        self.flask_app = create_app({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'WTF_CSRF_ENABLED': False,
            'SECRET_KEY': 'test-secret-intern-key-12345'
        })
        self.app = self.flask_app.test_client()

        with self.flask_app.app_context():
            db.create_all()
            # Create a test operator
            user = User(username='test_operator', email='operator@cyberguard.sec')
            user.set_password('P@ssw0rd12345!Secure')
            db.session.add(user)
            db.session.commit()
            self.user_id = user.id

    def tearDown(self):
        with self.flask_app.app_context():
            db.session.remove()
            db.drop_all()

    def login(self, username='test_operator', password='P@ssw0rd12345!Secure'):
        return self.app.post('/login', data={
            'identifier': username,
            'password': password
        }, follow_redirects=True)

    # -------------------------------------------------------------------------
    # 1. Breach Checker Tests (HIBP k-Anonymity + Local Fallback)
    # -------------------------------------------------------------------------
    def test_local_breach_check(self):
        is_breached, count, source = check_breach_local('password')
        self.assertTrue(is_breached)
        self.assertGreater(count, 0)
        self.assertIn('Local', source)

    def test_hibp_known_breach(self):
        # Test HIBP k-Anonymity live lookup for 'password'
        is_breached, count, source = check_breach_hibp_k_anonymity('password')
        self.assertTrue(is_breached)
        self.assertGreater(count, 1000000)
        self.assertIn('HaveIBeenPwned', source)

    def test_hibp_clean_high_entropy_password(self):
        # A 40-character pseudo-random string is virtually guaranteed unbreached
        clean_pwd = "X9#kL8$vM2!qW5@zP1*yT7^uR3&bN6~dJ4%eK0"
        is_breached, count, source = check_breach_hibp_k_anonymity(clean_pwd)
        self.assertFalse(is_breached)
        self.assertEqual(count, 0)

    def test_check_password_breach_hybrid(self):
        result = check_password_breach('password')
        self.assertTrue(result['is_breached'])
        self.assertGreater(result['count'], 0)

    def test_api_check_breach_endpoint(self):
        res = self.app.post('/api/check-breach',
                            data=json.dumps({'password': 'password'}),
                            content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data['is_breached'])
        self.assertGreater(data['count'], 0)

    # -------------------------------------------------------------------------
    # 2. Recommendations Engine Tests
    # -------------------------------------------------------------------------
    def test_recommendations_engine_for_weak_password(self):
        recs = SecurityRecommendationsEngine.generate_recommendations(
            password='123',
            score=15,
            entropy=14.2,
            criteria={'length8': False, 'length12': False, 'has_upper': False, 'has_symbol': False},
            warnings=[{'category': 'PATTERN', 'message': 'Sequential digits'}],
            is_breached=True,
            breach_count=5000000
        )
        self.assertIsInstance(recs, list)
        self.assertGreater(len(recs), 0)
        # Verify critical breach alert is prioritized first
        self.assertEqual(recs[0]['severity'], 'CRITICAL')
        self.assertEqual(recs[0]['id'], 'CRIT_BREACHED')
        self.assertIn('breach', recs[0]['message'].lower())

    def test_recommendations_engine_for_strong_password(self):
        recs = SecurityRecommendationsEngine.generate_recommendations(
            password='K9#mQ8$vP2!wR5@zT1*',
            score=95,
            entropy=92.5,
            criteria={'length8': True, 'length12': True, 'has_upper': True, 'has_symbol': True},
            warnings=[],
            is_breached=False,
            breach_count=0
        )
        self.assertIsInstance(recs, list)
        # Should include OPTIMAL / SUCCESS feedback
        has_optimal = any(r['severity'] == 'OPTIMAL' for r in recs)
        self.assertTrue(has_optimal)

    # -------------------------------------------------------------------------
    # 3. PDF Exporter Tests (ReportLab generation)
    # -------------------------------------------------------------------------
    def test_generate_pdf_report(self):
        analysis_mock = {
            'score': 85,
            'status': 'Strong',
            'length': 16,
            'pool_size': 72,
            'entropy_metrics': {
                'bits': 74.2,
                'combinations_display': '1.24 × 10²¹',
                'difficulty_label': 'High Resilience',
                'resistance_tier': 'Enterprise Hardened',
                'scenarios': {
                    'cluster': '4.2 Years',
                    'single_gpu': '4,200 Years',
                    'throttled': 'Centuries'
                }
            },
            'criteria': {
                'length8': True,
                'length12': True,
                'has_upper': True,
                'has_lower': True,
                'has_digit': True,
                'has_symbol': True,
                'no_patterns': True,
                'not_breached': True
            },
            'breach_info': {
                'is_breached': False,
                'count': 0,
                'source': 'HaveIBeenPwned API'
            },
            'warnings': [],
            'recommendations_detailed': [
                {
                    'id': 'OPT_EXCELLENT',
                    'severity': 'OPTIMAL',
                    'title': 'High Entropy Certified',
                    'message': 'Password exceeds 70 bits of Shannon entropy.',
                    'action': 'Maintain credential rotation every 90 days.'
                }
            ]
        }

        pdf_bytes = generate_pdf_report(analysis_mock, password_preview="K9#mQ8$vP2!wR5@z", operator_name="test_operator")
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b'%PDF-'))
        self.assertGreater(len(pdf_bytes), 1000)

    # -------------------------------------------------------------------------
    # 4. User Profile Tests
    # -------------------------------------------------------------------------
    def test_profile_page_requires_auth(self):
        res = self.app.get('/profile', follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn('/login', res.headers['Location'])

    def test_profile_page_authenticated(self):
        self.login()
        res = self.app.get('/profile')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'test_operator', res.data)
        self.assertIn(b'operator@cyberguard.sec', res.data)

    def test_profile_email_update(self):
        self.login()
        res = self.app.post('/profile/update', data={
            'email': 'new_operator@cyberguard.sec'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        with self.flask_app.app_context():
            u = db.session.get(User, self.user_id)
            self.assertEqual(u.email, 'new_operator@cyberguard.sec')

    def test_profile_change_password(self):
        self.login()
        res = self.app.post('/profile/change-password', data={
            'current_password': 'P@ssw0rd12345!Secure',
            'new_password': 'NewStrongP@ssw0rd999!',
            'confirm_password': 'NewStrongP@ssw0rd999!'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        # Verify old password fails and new password succeeds
        with self.flask_app.app_context():
            u = db.session.get(User, self.user_id)
            self.assertFalse(u.check_password('P@ssw0rd12345!Secure'))
            self.assertTrue(u.check_password('NewStrongP@ssw0rd999!'))

    def test_profile_purge_vault(self):
        self.login()
        with self.flask_app.app_context():
            sp = SavedPassword(user_id=self.user_id, label='Test Item', password='secretpassword', length=14)
            db.session.add(sp)
            db.session.commit()
            self.assertEqual(SavedPassword.query.filter_by(user_id=self.user_id).count(), 1)

        res = self.app.post('/profile/purge-vault', follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        with self.flask_app.app_context():
            self.assertEqual(SavedPassword.query.filter_by(user_id=self.user_id).count(), 0)

    # -------------------------------------------------------------------------
    # 5. Audit Logging Tests
    # -------------------------------------------------------------------------
    def test_audit_log_created_on_login(self):
        self.login()
        with self.flask_app.app_context():
            logs = AuditLog.query.filter_by(user_id=self.user_id, event_type='AUTH_LOGIN_SUCCESS').all()
            self.assertGreater(len(logs), 0)

    def test_audit_logs_api(self):
        self.login()
        res = self.app.get('/api/audit-logs')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data['success'])
        self.assertGreaterEqual(len(data['logs']), 1)

    # -------------------------------------------------------------------------
    # 6. PDF Export Endpoint Tests
    # -------------------------------------------------------------------------
    def test_api_export_pdf_direct(self):
        res = self.app.post('/api/export-pdf',
                            data=json.dumps({
                                'password': 'X7#kL9$vM2!qW5@zP1',
                                'analysis': {'score': 90, 'status': 'Very Strong'}
                            }),
                            content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.content_type, 'application/pdf')
        self.assertTrue(res.data.startswith(b'%PDF-'))

    def test_api_export_saved_report_pdf(self):
        self.login()
        report_id = None
        with self.flask_app.app_context():
            rep = StrengthReport(
                user_id=self.user_id,
                password_preview='P@ssw0rd12•••••',
                score=88,
                status='Strong',
                entropy=72.5,
                crack_time='10 years',
                pool_size=64,
                warnings_count=0,
                is_breached=False,
                details_json=json.dumps({
                    'score': 88,
                    'status': 'Strong',
                    'entropy_metrics': {'bits': 72.5, 'difficulty_label': 'High', 'resistance_tier': 'Hardened'},
                    'criteria': {'length8': True, 'length12': True, 'has_upper': True, 'has_symbol': True},
                    'breach_info': {'is_breached': False, 'count': 0}
                })
            )
            db.session.add(rep)
            db.session.commit()
            report_id = rep.id

        res = self.app.get(f'/api/export-report-pdf/{report_id}')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.content_type, 'application/pdf')
        self.assertTrue(res.data.startswith(b'%PDF-'))

if __name__ == '__main__':
    unittest.main()
