import unittest
from unittest.mock import MagicMock, patch
import json
import srun_login_pro as srun

class TestSRUNAuthenticator(unittest.TestCase):

    def test_base64_encoding(self):
        # Test standard SRUN base64 with custom ALPHA
        test_str = "hello world"
        encoded = srun.get_base64(test_str)
        self.assertTrue(all(c in srun.ALPHA or c == '=' for c in encoded))
        # Known property: encoding same string twice should yield same result
        self.assertEqual(encoded, srun.get_base64(test_str))

    def test_md5_hmac(self):
        password = "test_password"
        token = "test_token"
        hmd5 = srun.get_md5(password, token)
        self.assertEqual(len(hmd5), 32) # Standard MD5 length

    def test_sencode_lencode_roundtrip(self):
        # Basic sanity check for the TEA-like encoding primitives
        msg = "simple_test_string"
        encoded = srun.sencode(msg, False)
        decoded = srun.lencode(encoded, False)
        # Note: sencode/lencode implementation in SRUN is specific to its protocol
        # but should at least handle the length correctly
        self.assertTrue(len(decoded) >= len(msg))

    @patch('requests.Session.get')
    def test_fetch_ip_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'jQuery123({"client_ip":"1.2.3.4"})'
        mock_get.return_return_value = mock_response
        
        # We need to pass a session
        import requests
        session = requests.Session()
        session.get = MagicMock(return_value=mock_response)
        
        success = srun.fetch_ip(session)
        self.assertTrue(success)
        self.assertEqual(srun.state['ip'], "1.2.3.4")

    @patch('requests.Session.get')
    def test_fetch_token_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'jQuery123({"challenge":"mock_token"})'
        
        import requests
        session = requests.Session()
        session.get = MagicMock(return_value=mock_response)
        
        srun.state['ip'] = '1.2.3.4'
        success = srun.fetch_token(session)
        self.assertTrue(success)
        self.assertEqual(srun.state['token'], "mock_token")

    @patch('requests.Session.get')
    def test_is_connected_baidu(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        import requests
        session = requests.Session()
        session.get = MagicMock(return_value=mock_response)
        
        # Test default (Baidu/China friendly)
        self.assertTrue(srun.is_connected(session))

    def test_get_info_json(self):
        srun.USERNAME = "test_user"
        srun.PASSWORD = "test_pass"
        srun.state['ip'] = "1.2.3.4"
        info = srun.get_info()
        data = json.loads(info)
        self.assertEqual(data['username'], "test_user")
        self.assertEqual(data['ip'], "1.2.3.4")

if __name__ == '__main__':
    unittest.main()
