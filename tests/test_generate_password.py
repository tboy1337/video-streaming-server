"""
Unit tests for generate_password module
---------------------------------------
Tests for password generation utility functionality.
"""

import string
from unittest.mock import MagicMock, patch

import pytest

import generate_password


class TestPasswordGeneration:
    """Test cases for password generation"""

    def test_generate_strong_password_default_length(self):
        """Test password generation with default length"""
        password = generate_password.generate_strong_password()

        assert len(password) == 35
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert sum(c.isdigit() for c in password) >= 3
        assert sum(c in string.punctuation for c in password) >= 2

    def test_generate_strong_password_custom_length(self):
        """Test password generation with custom length"""
        password = generate_password.generate_strong_password(20)

        assert len(password) == 20
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert sum(c.isdigit() for c in password) >= 3
        assert sum(c in string.punctuation for c in password) >= 2

    def test_generate_strong_password_uniqueness(self):
        """Test that generated passwords are unique"""
        password1 = generate_password.generate_strong_password()
        password2 = generate_password.generate_strong_password()

        assert password1 != password2

    def test_generate_strong_password_requirements(self):
        """Test password meets all requirements"""
        password = generate_password.generate_strong_password(15)

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        digit_count = sum(c.isdigit() for c in password)
        punct_count = sum(c in string.punctuation for c in password)

        assert has_lower, "Password should contain lowercase letters"
        assert has_upper, "Password should contain uppercase letters"
        assert digit_count >= 3, "Password should contain at least 3 digits"
        assert punct_count >= 2, "Password should contain at least 2 punctuation marks"


class TestMainFunction:
    """Test cases for the main interactive function"""

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_with_generated_password(self, mock_print, mock_input):
        """Test main function with generated password option"""
        mock_input.side_effect = ["y"]  # Choose generated password

        with patch("generate_password.generate_strong_password") as mock_gen:
            mock_gen.return_value = "TestPass123!"
            with patch("generate_password.generate_password_hash") as mock_hash:
                mock_hash.return_value = "hashed_password"

                generate_password.main()

                # Verify generate_password_hash was called
                mock_hash.assert_called_once_with("TestPass123!")

                # Verify appropriate print calls were made
                mock_print.assert_any_call("\nGenerated password: TestPass123!")
                mock_print.assert_any_call(
                    "IMPORTANT: Save this password in a secure location!"
                )

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_with_custom_password_valid_first_try(self, mock_print, mock_input):
        """Test main function with custom password that's valid on first try"""
        mock_input.side_effect = [
            "n",
            "MyPassword123!",
            "MyPassword123!",
        ]  # No generated, password, confirm

        with patch("generate_password.generate_password_hash") as mock_hash:
            mock_hash.return_value = "hashed_password"

            generate_password.main()

            # Verify generate_password_hash was called with custom password
            mock_hash.assert_called_once_with("MyPassword123!")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_with_custom_password_too_short(self, mock_print, mock_input):
        """Test main function with custom password that's too short"""
        mock_input.side_effect = [
            "n",  # No generated password
            "short",  # Too short password
            "ValidPass123!",  # Valid password
            "ValidPass123!",  # Confirm password
        ]

        with patch("generate_password.generate_password_hash") as mock_hash:
            mock_hash.return_value = "hashed_password"

            generate_password.main()

            # Verify error message was printed
            mock_print.assert_any_call(
                "Password is too short! Use at least 8 characters."
            )
            mock_hash.assert_called_once_with("ValidPass123!")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_with_password_mismatch(self, mock_print, mock_input):
        """Test main function with password confirmation mismatch"""
        mock_input.side_effect = [
            "n",  # No generated password
            "MyPassword123!",  # Valid password
            "DifferentPass",  # Mismatched confirmation
            "MyPassword123!",  # Valid password again
            "MyPassword123!",  # Matching confirmation
        ]

        with patch("generate_password.generate_password_hash") as mock_hash:
            mock_hash.return_value = "hashed_password"

            generate_password.main()

            # Verify error message was printed
            mock_print.assert_any_call("Passwords don't match! Try again.")
            mock_hash.assert_called_once_with("MyPassword123!")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_prints_final_instructions(self, mock_print, mock_input):
        """Test that main function prints final instructions"""
        mock_input.side_effect = ["y"]  # Choose generated password

        with patch("generate_password.generate_strong_password"):
            with patch("generate_password.generate_password_hash") as mock_hash:
                mock_hash.return_value = "test_hash_value"

                generate_password.main()

                # Check that important instructions are printed
                expected_calls = [
                    "Video Streaming Server - Password Setup",
                    "\nInstructions:",
                    "1. Copy the password hash above",
                    "2. Open streaming_server.py",
                    "3. Replace 'your-generated-hash-goes-here' with the copied hash",
                    "4. Save the file and run with: python streaming_server.py",
                    "\nYou'll use the username 'friend' and your chosen password to log in",
                ]

                for expected_call in expected_calls:
                    mock_print.assert_any_call(expected_call)
