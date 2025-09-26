import io
from unittest import TestCase
from unittest import mock
from unittest.mock import patch, MagicMock

import flake8
from passwault.core import cli

class TestCli(TestCase):
    
    def setUp(self):
        self.ctx = MagicMock()
    
    @patch("passwault.core.cli.register")
    def test_register_with_all_arguments(self, mock_register):
        test_args = ["register", "-u", "johndoe", "-p", "mypass", "-r", "admin"]
        cli.cli(self.ctx, test_args)
        
        mock_register.assert_called_once_with("johndoe", "mypass", "admin", self.ctx)
    
    @patch("passwault.core.cli.register")
    def test_register_without_required_arguments(self, mock_register):
        cases = [
            ["register", "-p", "passwrd", "-r", "admin"],  # missing username
            ["register", "-u", "johndoe", "-p", "passw"],  # missing role
        ]

        for args in cases:
            with self.subTest(args=args):
                fake_stderr = io.StringIO()
                with patch("sys.stderr", fake_stderr):
                    with self.assertRaises(SystemExit) as cm:
                        cli.cli(self.ctx, args)
        
                    mock_register.assert_not_called()
                    self.assertEqual(cm.exception.code, 2) 
        
    @patch("passwault.core.cli.login")
    def test_login_with_all_arguments(self, mock_login):
        test_args = ["login", "-u", "johndoe", "-p", "mypass"]
        cli.cli(self.ctx, test_args)
        
        mock_login.assert_called_once_with("johndoe", "mypass", self.ctx)


    @patch("passwault.core.cli.login")
    def test_login_without_required_arguments(self, mock_login):
        cases = [
            ["login", "-p", "passwrd"],  # missing username
        ]

        for args in cases:
            with self.subTest(args=args):
                fake_stderr = io.StringIO()
                with patch("sys.stderr", fake_stderr):
                    with self.assertRaises(SystemExit) as cm:
                        cli.cli(self.ctx, args)
        
                    mock_login.assert_not_called()
                    self.assertEqual(cm.exception.code, 2) 
    
    @patch("passwault.core.cli.logout") 
    def test_logout(self, mock_logout):
        cli.cli(self.ctx, ["logout"])

        mock_logout.assert_called()
    
    @patch("passwault.core.cli.generate_pw")
    def test_generate_with_all_arguments(self, mock_generate):
        test_args = ["generate", "-sdu",  "-l", "30"]

        cli.cli(self.ctx, test_args)

        mock_generate.assert_called_once_with(30, True, True, True)
    
    @patch("passwault.core.cli.generate_pw")
    def test_generate_with_no_arguments(self, mock_generate):
        test_args = ["generate"]

        cli.cli(self.ctx, test_args)

        mock_generate.assert_called_once_with(10, False, False, False)
    
    @patch("passwault.core.cli.valid_file", lambda x: x)
    @patch("passwault.core.cli.save_pw")
    def test_save_password_with_file(self, mock_save_pw):
        test_args = ["save_password", "-f", "passwords.csv"]
        
        cli.cli(self.ctx, test_args) 

        mock_save_pw.assert_called_once_with(None, None, None, "passwords.csv", self.ctx)

    @patch("passwault.core.cli.save_pw")
    def test_save_password_without_file(self, mock_save_pw):
        test_args = ["save_password", "-p", "secret", "-n", "gmail", "-u", "myuser"]
        cli.cli(self.ctx, test_args)

        mock_save_pw.assert_called_once_with("myuser", "secret", "gmail", None, self.ctx)
        
    @patch("passwault.core.cli.save_pw")
    def test_save_password_without_p_or_n(self, mock_save_pw):
        cases = [
            ["save_password", "-p", "s3cret"],
            ["save_password", "-n", "label"],
            ["save_password"]
        ]
        
        for args in cases:
            with self.subTest(args=args):
                fake_stderr = io.StringIO()
                with patch("sys.stderr", fake_stderr):
                    with self.assertRaises(SystemExit) as cm:
                        cli.cli(self.ctx, args)
        
                    mock_save_pw.assert_not_called()
                    self.assertEqual(cm.exception.code, 2) 