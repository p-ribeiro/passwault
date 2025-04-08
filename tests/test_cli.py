# from unittest.mock import MagicMock, patch

# from pytest import MonkeyPatch

# from passwault.core.cli import logged_in, start
# from passwault.core.commands import authenticator


# def test_start_register(monkeypatch: MonkeyPatch) -> None:
#     inputs = iter(["register", "user1", "pass1", "admin"])

#     monkeypatch.setattr("builtins.input", lambda _: next(inputs))
#     monkeypatch.setattr("os.system", lambda _: None)

#     with patch("vault.core.cli.register") as mock_register:
#         start()
#         mock_register.assert_called_once_with("user1", "pass1", "admin")


# def test_start_login(monkeypatch: MonkeyPatch) -> None:
#     inputs = iter(["login", "user1", "pass1"])

#     monkeypatch.setattr("builtins.input", lambda _: next(inputs))
#     monkeypatch.setattr("os.system", lambda _: None)

#     with patch("vault.core.cli.login") as mock_login:
#         mock_logged_in = MagicMock()
#         with patch("vault.core.cli.logged_in", mock_logged_in):
#             start()
#             mock_login.assert_called_once_with("user1", "pass1", mock_logged_in)
