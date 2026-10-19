import unittest
from app import create_app
from models import db
from analyzer import (
    analyze_password,
    calculate_entropy_metrics,
    estimate_brute_force_scenarios,
    detect_common_password,
    detect_repeated_characters,
    detect_sequential_patterns,
    detect_keyboard_patterns,
    detect_dictionary_words
)
from generator import generate_secure_password

class TestPasswordAnalyzer(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'
        })
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_entropy_and_difficulty_calculation(self):
        # 1. Very weak password (< 28 bits)
        weak_ent = calculate_entropy_metrics('12345')
        self.assertLess(weak_ent['bits'], 28)
        self.assertEqual(weak_ent['difficulty_rating'], 'Trivial')
        self.assertEqual(weak_ent['difficulty_badge'], 'badge-trivial')

        # 2. Moderate password (36 - 60 bits)
        med_ent = calculate_entropy_metrics('Kx9#mQ!8')
        self.assertGreaterEqual(med_ent['bits'], 36)
        self.assertIn(med_ent['difficulty_rating'], ['Moderate', 'Strong'])

        # 3. Military grade password (>= 80 bits)
        strong_ent = calculate_entropy_metrics('Xk9#vL2$wP7!zM4@8&')
        self.assertGreaterEqual(strong_ent['bits'], 80)
        self.assertEqual(strong_ent['difficulty_rating'], 'Military Grade')
        self.assertEqual(strong_ent['difficulty_badge'], 'badge-extreme')
        self.assertIn('× 10^', strong_ent['combinations_display'])

    def test_brute_force_scenarios(self):
        scenarios = estimate_brute_force_scenarios('Xk9#vL2$wP7!zM4@')
        self.assertIn('gpu_cluster', scenarios)
        self.assertIn('single_gpu', scenarios)
        self.assertIn('online_fast', scenarios)
        self.assertIn('online_throttled', scenarios)
        self.assertIn('years', scenarios['gpu_cluster']['time'].lower() + scenarios['gpu_cluster']['time'].lower())

    def test_pattern_detection(self):
        # Common passwords
        common_warns = detect_common_password('123456')
        self.assertTrue(any(w['category'] == 'Common Password' for w in common_warns))

        # Repeated characters
        repeat_warns = detect_repeated_characters('aaaa12345')
        self.assertTrue(any(w['category'] == 'Repeated Characters' for w in repeat_warns))

        # Sequential patterns
        seq_num = detect_sequential_patterns('myPass123456')
        self.assertTrue(any(w['category'] == 'Sequential Pattern' for w in seq_num))

        # Keyboard patterns
        key_warns = detect_keyboard_patterns('secure_qwerty_pass')
        self.assertTrue(any(w['category'] == 'Keyboard Pattern' for w in key_warns))

        # Dictionary words
        dict_warns = detect_dictionary_words('mysecretpassword99')
        self.assertTrue(any(w['category'] == 'Dictionary Word' for w in dict_warns))

    def test_api_analyze_with_entropy_cards(self):
        res = self.client.post('/api/analyze', json={'password': 'MySecurePass#2026!'})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('entropy_metrics', data)
        self.assertIn('attack_scenarios', data)
        self.assertGreater(data['entropy_metrics']['bits'], 50)
        self.assertIn('gpu_cluster', data['attack_scenarios'])

    def test_secure_password_generator(self):
        # Test custom length
        pwd_16 = generate_secure_password(length=16, include_upper=True, include_lower=True, include_digits=True, include_symbols=True)
        self.assertEqual(len(pwd_16), 16)
        self.assertTrue(any(c.isupper() for c in pwd_16))
        self.assertTrue(any(c.islower() for c in pwd_16))
        self.assertTrue(any(c.isdigit() for c in pwd_16))
        self.assertTrue(any(not c.isalnum() for c in pwd_16))

        # Test length 32
        pwd_32 = generate_secure_password(length=32)
        self.assertEqual(len(pwd_32), 32)

        # Test exclusions: no symbols, no digits
        pwd_alpha = generate_secure_password(length=20, include_upper=True, include_lower=True, include_digits=False, include_symbols=False)
        self.assertEqual(len(pwd_alpha), 20)
        self.assertTrue(pwd_alpha.isalpha())

        # Test numbers only
        pwd_digits = generate_secure_password(length=10, include_upper=False, include_lower=False, include_digits=True, include_symbols=False, exclude_ambiguous=False)
        self.assertEqual(len(pwd_digits), 10)
        self.assertTrue(pwd_digits.isdigit())

    def test_api_generate_endpoint(self):
        res = self.client.post('/api/generate', json={
            'length': 24,
            'upper': True,
            'lower': True,
            'digits': True,
            'symbols': True
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('password', data)
        self.assertIn('analysis', data)
        self.assertEqual(len(data['password']), 24)
        self.assertIn(data['analysis']['status'], ['Strong', 'Very Strong'])
        self.assertGreaterEqual(data['analysis']['score'], 80)

if __name__ == '__main__':
    unittest.main()

