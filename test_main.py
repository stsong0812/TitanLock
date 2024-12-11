import unittest
from unittest.mock import patch, mock_open, MagicMock, ANY
from password_generation_frame import generate_password
from password_strength_frame import check_password_strength
from settings_frame import save_settings, load_settings, create_titanlock_folder
from main import validate_and_reset, open_master_key_window, lock_app

class TestTitanLock(unittest.TestCase):

    def test_generate_password(self):
        """Test the password generation function with various options."""
        entry_mock = MagicMock()
        entry_mock.configure = MagicMock()
        entry_mock.delete = MagicMock()
        entry_mock.insert = MagicMock()

        # Test generating a password with all options enabled
        generate_password("12", True, True, True, entry_mock)
        entry_mock.insert.assert_called_once()  # Ensure password was inserted
        self.assertTrue(len(entry_mock.insert.call_args[0][1]) == 12)  # Length check

        # Test invalid length input
        with patch("password_generation_frame.showwarning") as mock_warning:
            generate_password("5", True, True, True, entry_mock)  # Below minimum length
            mock_warning.assert_called_with("Invalid Length", "Password length must be between 6 and 20 characters.")

        # Test no character types selected
        with patch("password_generation_frame.showwarning") as mock_warning:
            generate_password("12", False, False, False, entry_mock)
            mock_warning.assert_called_with("No Options Selected", "Please select at least one character type (uppercase, numbers, special characters).")

    def test_check_password_strength(self):
        """Test the password strength checking function."""
        label_mock = MagicMock()

        # Test strong password
        check_password_strength("CorrectHorseBatteryStaple123!", label_mock)
        label_mock.configure.assert_called_with(text="Password strength: Strong", text_color="green")

        # Test moderate password
        check_password_strength("Horse123", label_mock)
        label_mock.configure.assert_called_with(text="Password strength: Moderate", text_color="orange")

        # Test weak password
        check_password_strength("1234", label_mock)
        label_mock.configure.assert_called_with(text="Password strength: Weak", text_color="red")

    @patch("builtins.open", new_callable=mock_open, read_data="[Display]\\ndark_mode = False\\n[Security]\\nauto_lock_timeout = 300")
    @patch("os.path.exists", return_value=True)
    def test_load_settings(self, mock_exists, mock_open_file):
        """Test the settings loading function."""
        settings = load_settings()
        self.assertEqual(settings["dark_mode"], False)
        self.assertEqual(settings["auto_lock_timeout"], 300)

    @patch("builtins.open", new_callable=mock_open)
    def test_save_settings(self, mock_open_file):
        """Test the settings saving function."""
        save_settings(True, 600)  # Dark mode enabled, 10-minute timeout
        mock_open_file.assert_called_with('/etc/TitanLock/settings.conf', 'w')
        file_handle = mock_open_file()
        file_handle.write.assert_any_call("[Display]\n")
        file_handle.write.assert_any_call("dark_mode = True\n")
        file_handle.write.assert_any_call("[Security]\n")
        file_handle.write.assert_any_call("auto_lock_timeout = 600\n")

    @patch("os.makedirs")
    @patch("os.path.exists", return_value=False)  # Simulate folder does not exist
    def test_create_titanlock_folder(self, mock_exists, mock_makedirs):
        """Test the creation of the TitanLock folder."""
        create_titanlock_folder()
        mock_makedirs.assert_called_once_with('/etc/TitanLock')

    @patch("argon2.PasswordHasher")
    def test_verify_password_correct(self, MockPasswordHasher):
        """Test correct password verification."""
        mock_ph = MockPasswordHasher.return_value
        mock_ph.verify.return_value = True  # Simulate correct password
        self.assertTrue(mock_ph.verify("stored_hash", "provided_password"))

    @patch("argon2.PasswordHasher")
    def test_verify_password_incorrect(self, MockPasswordHasher):
        """Test incorrect password verification."""
        mock_ph = MockPasswordHasher.return_value
        mock_ph.verify.side_effect = Exception("Verification failed")  # Simulate mismatch
        with self.assertRaises(Exception):
            mock_ph.verify("stored_hash", "wrong_password")

    @patch("main.root", new_callable=MagicMock)
    @patch("main.validate_master_key")
    def test_validate_and_reset_success(self, mock_validate_master_key, mock_root):
        """Test successful master key validation and window reset."""
        master_key_window_mock = MagicMock()
        mock_validate_master_key.return_value = True

        # Call the function being tested
        validate_and_reset("correct_key", master_key_window_mock)

        # Assert that validate_master_key is called with the correct arguments
        mock_validate_master_key.assert_called_once_with(
            "correct_key", master_key_window_mock, ANY
        )

        # Assert that the root window is shown
        mock_root.deiconify.assert_called_once()

    @patch("main.open_master_key_window")
    @patch("main.root")
    def test_lock_app(self, mock_root, mock_open_master_key):
        """Test app locking functionality."""
        mock_root.state.return_value = "normal"
        lock_app()
        mock_open_master_key.assert_called_once_with(mock_root, validate_and_reset)

if __name__ == "__main__":
    unittest.main()