import unittest
from app import create_app
from models import db, User, SavedPassword, StrengthReport
import bcrypt

class TestUserAuthAndVault(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'SECRET_KEY': 'test-secret-key-12345'
        })
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_bcrypt_hashing_on_user_model(self):
        user = User(username='cipher_master', email='cipher@shield.io')
        plain_pwd = 'SuperSecret#Password2026!'
        user.set_password(plain_pwd)

        # Ensure password is not stored plaintext
        self.assertNotEqual(user.password_hash, plain_pwd)
        # Ensure it is a valid bcrypt hash starting with $2b$
        self.assertTrue(user.password_hash.startswith('$2b$'))
        # Verify checking password returns true for correct and false for wrong
        self.assertTrue(user.check_password(plain_pwd))
        self.assertFalse(user.check_password('WrongPassword123!'))

    def test_user_registration_form_flow(self):
        # Successful registration via Form
        res = self.client.post('/register', data={
            'username': 'neo_matrix',
            'email': 'neo@zion.org',
            'password': 'RedPill#Secure123',
            'confirm_password': 'RedPill#Secure123'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'neo_matrix', res.data)

        with self.app.app_context():
            user = User.query.filter_by(username='neo_matrix').first()
            self.assertIsNotNone(user)
            self.assertEqual(user.email, 'neo@zion.org')
            self.assertTrue(user.check_password('RedPill#Secure123'))

        # Logout so we can test unauthenticated registration errors
        self.client.get('/logout')

        # Duplicate username rejection
        res_dup = self.client.post('/register', data={
            'username': 'neo_matrix',
            'email': 'other@zion.org',
            'password': 'Another#Password99',
            'confirm_password': 'Another#Password99'
        })
        self.assertEqual(res_dup.status_code, 200)
        self.assertIn(b'already registered', res_dup.data)

        # Mismatched passwords rejection
        res_mismatch = self.client.post('/register', data={
            'username': 'trinity',
            'email': 'trinity@zion.org',
            'password': 'Password123!',
            'confirm_password': 'DifferentPassword456!'
        })
        self.assertEqual(res_mismatch.status_code, 200)
        self.assertIn(b'Passwords do not match', res_mismatch.data)

    def test_user_registration_json_api(self):
        res = self.client.post('/register', json={
            'username': 'morpheus',
            'email': 'morpheus@zion.org',
            'password': 'BluePill#Escape99',
            'confirm_password': 'BluePill#Escape99'
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['redirect'], '/dashboard')

    def test_user_login_and_logout_flow(self):
        # Register user first
        with self.app.app_context():
            user = User(username='agent_smith', email='smith@matrix.net')
            user.set_password('MrAnderson#2026')
            db.session.add(user)
            db.session.commit()

        # Login with username
        res_user = self.client.post('/login', data={
            'identifier': 'agent_smith',
            'password': 'MrAnderson#2026'
        }, follow_redirects=True)
        self.assertEqual(res_user.status_code, 200)
        self.assertIn(b'agent_smith', res_user.data)

        # Logout
        res_logout = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(res_logout.status_code, 200)
        self.assertIn(b'logged out', res_logout.data)

        # Login with email
        res_email = self.client.post('/login', data={
            'identifier': 'smith@matrix.net',
            'password': 'MrAnderson#2026'
        }, follow_redirects=True)
        self.assertEqual(res_email.status_code, 200)
        self.assertIn(b'agent_smith', res_email.data)

        # Login with wrong password
        self.client.get('/logout')
        res_bad = self.client.post('/login', data={
            'identifier': 'agent_smith',
            'password': 'WrongPassword123'
        })
        self.assertEqual(res_bad.status_code, 200)
        self.assertIn(b'Invalid credentials', res_bad.data)

    def test_auth_status_api(self):
        # Not logged in
        res = self.client.get('/api/auth/status')
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.get_json()['authenticated'])

        # Register and login
        self.client.post('/register', json={
            'username': 'tank_operator',
            'email': 'tank@zion.org',
            'password': 'Nebuchadnezzar#2026',
            'confirm_password': 'Nebuchadnezzar#2026'
        })

        res_auth = self.client.get('/api/auth/status')
        self.assertEqual(res_auth.status_code, 200)
        data = res_auth.get_json()
        self.assertTrue(data['authenticated'])
        self.assertEqual(data['user']['username'], 'tank_operator')

    def test_saved_password_vault_crud_sqlite(self):
        # Register user
        self.client.post('/register', json={
            'username': 'vault_tester',
            'email': 'vault@tester.com',
            'password': 'VaultSecure#Password123',
            'confirm_password': 'VaultSecure#Password123'
        })

        # Save generated password to vault
        res_save = self.client.post('/api/save-generated', json={
            'password': 'kP9$vM2!wQ8#zR5@',
            'label': 'Production DB Key'
        })
        self.assertEqual(res_save.status_code, 200)
        save_data = res_save.get_json()
        self.assertTrue(save_data['success'])
        item_id = save_data['item']['id']
        self.assertEqual(save_data['item']['label'], 'Production DB Key')
        self.assertEqual(save_data['item']['password'], 'kP9$vM2!wQ8#zR5@')

        # Retrieve saved passwords for user
        res_get = self.client.get('/api/user/saved-passwords')
        self.assertEqual(res_get.status_code, 200)
        get_data = res_get.get_json()
        self.assertEqual(len(get_data['passwords']), 1)
        self.assertEqual(get_data['passwords'][0]['id'], item_id)

        # Delete saved password
        res_del = self.client.delete(f'/api/user/saved-passwords/{item_id}')
        self.assertEqual(res_del.status_code, 200)
        self.assertTrue(res_del.get_json()['success'])

        # Confirm list is now empty
        res_get2 = self.client.get('/api/user/saved-passwords')
        self.assertEqual(len(res_get2.get_json()['passwords']), 0)

    def test_strength_report_vault_crud_sqlite(self):
        # Register user
        self.client.post('/register', json={
            'username': 'report_tester',
            'email': 'report@tester.com',
            'password': 'Report#MasterKey999',
            'confirm_password': 'Report#MasterKey999'
        })

        # Save strength report
        res_save = self.client.post('/api/save-report', json={
            'password': 'SecureP@ssw0rd2026!',
            'analysis': {
                'score': 85,
                'status': 'Very Strong',
                'entropy': 78.4,
                'crack_time': {'offline_fast': '350 years'},
                'entropy_metrics': {'pool_size': 94},
                'warnings': [],
                'is_breached': False
            }
        })
        self.assertEqual(res_save.status_code, 200)
        save_data = res_save.get_json()
        self.assertTrue(save_data['success'])
        report_id = save_data['item']['id']
        self.assertEqual(save_data['item']['score'], 85)
        self.assertEqual(save_data['item']['status'], 'Very Strong')

        # Retrieve user reports
        res_get = self.client.get('/api/user/reports')
        self.assertEqual(res_get.status_code, 200)
        self.assertEqual(len(res_get.get_json()['reports']), 1)

        # Delete report
        res_del = self.client.delete(f'/api/user/reports/{report_id}')
        self.assertEqual(res_del.status_code, 200)
        self.assertTrue(res_del.get_json()['success'])

        # Confirm list is now empty
        res_get2 = self.client.get('/api/user/reports')
        self.assertEqual(len(res_get2.get_json()['reports']), 0)

    def test_dashboard_access_control(self):
        # Guest user redirected to login
        res_guest = self.client.get('/dashboard')
        self.assertEqual(res_guest.status_code, 302)
        self.assertIn('/login', res_guest.headers['Location'])

        # Registered user can view dashboard
        self.client.post('/register', json={
            'username': 'dashboard_user',
            'email': 'dash@user.com',
            'password': 'DashPassword#2026',
            'confirm_password': 'DashPassword#2026'
        })
        res_auth = self.client.get('/dashboard')
        self.assertEqual(res_auth.status_code, 200)
        self.assertIn(b'Operator Vault', res_auth.data)
        self.assertIn(b'dashboard_user', res_auth.data)

    def test_cybersecurity_dashboard_and_analytics(self):
        # 1. Test /analytics page renders with Chart.js
        res_page = self.client.get('/analytics')
        self.assertEqual(res_page.status_code, 200)
        self.assertIn(b'chart.js', res_page.data.lower())
        self.assertIn(b'Strength Distribution', res_page.data)
        self.assertIn(b'TOTAL ANALYZED', res_page.data)
        self.assertIn(b'WEAK PASSWORDS', res_page.data)
        self.assertIn(b'STRONG PASSWORDS', res_page.data)

        # 2. Test /api/analytics/stats API
        res_stats = self.client.get('/api/analytics/stats')
        self.assertEqual(res_stats.status_code, 200)
        stats = res_stats.get_json()
        self.assertIn('total_analyzed', stats)
        self.assertIn('avg_score', stats)
        self.assertIn('weak_count', stats)
        self.assertIn('strong_count', stats)
        self.assertIn('distribution', stats)
        self.assertIn('Weak', stats['distribution'])
        self.assertIn('Strong', stats['distribution'])

        # 3. Seed demo data and verify counts update
        res_seed = self.client.post('/api/analytics/seed-demo')
        self.assertEqual(res_seed.status_code, 200)
        seed_data = res_seed.get_json()
        self.assertTrue(seed_data['success'])
        self.assertGreater(seed_data['stats']['total_analyzed'], 0)
        self.assertGreater(seed_data['stats']['weak_count'] + seed_data['stats']['strong_count'], 0)

if __name__ == '__main__':
    unittest.main()

