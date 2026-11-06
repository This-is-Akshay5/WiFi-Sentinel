import subprocess
import unittest
from types import SimpleNamespace

from core.credential_access import CredentialAccessError, retrieve_current_wifi_credential


class CurrentWifiCredentialTests(unittest.TestCase):
    def test_requires_current_connected_ssid_before_any_os_lookup(self):
        calls = []
        with self.assertRaisesRegex(CredentialAccessError, "currently connected"):
            retrieve_current_wifi_credential("Darwin", {"connected": False, "ssid": "Other"},
                                              run_command=lambda *args, **kwargs: calls.append(args))
        self.assertEqual(calls, [])

    def test_macos_uses_keychain_cli_for_only_the_connected_ssid(self):
        calls = []
        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args, 0, stdout="current-network-secret\n", stderr="")
        password = retrieve_current_wifi_credential("Darwin", {"connected": True, "ssid": "Current Network"},
                                                    run_command=runner)
        self.assertEqual(password, "current-network-secret")
        self.assertEqual(calls[0][0][4:6], ["-a", "Current Network"])
        self.assertIs(calls[0][1]["capture_output"], True)
        self.assertIs(calls[0][1]["shell"], False)

    def test_macos_denial_is_sanitized_and_does_not_echo_command_output(self):
        def runner(args, **kwargs):
            return subprocess.CompletedProcess(args, 36, stdout="never-echo-this-secret", stderr="denied")
        with self.assertRaises(CredentialAccessError) as error:
            retrieve_current_wifi_credential("Darwin", {"connected": True, "ssid": "Current Network"},
                                              run_command=runner)
        self.assertNotIn("never-echo-this-secret", str(error.exception))

    def test_windows_requires_os_elevated_permission_and_reads_current_profile_only(self):
        calls = []
        def runner(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, stdout="    Key Content            : current-network-secret\r\n", stderr="")
        with self.assertRaisesRegex(CredentialAccessError, "administrator"):
            retrieve_current_wifi_credential("Windows", {"connected": True, "ssid": "Current Network"},
                                              run_command=runner, is_admin=False)
        self.assertEqual(calls, [])
        password = retrieve_current_wifi_credential("Windows", {"connected": True, "ssid": "Current Network"},
                                                    run_command=runner, is_admin=True)
        self.assertEqual(password, "current-network-secret")
        self.assertEqual(calls[0], ["netsh", "wlan", "show", "profile", "name=Current Network", "key=clear"])
        self.assertFalse(any("Other" in str(arg) for arg in calls[0]))

    def test_unsupported_platform_does_not_attempt_credential_access(self):
        calls = []
        with self.assertRaisesRegex(CredentialAccessError, "not supported"):
            retrieve_current_wifi_credential("Linux", {"connected": True, "ssid": "Current Network"},
                                              run_command=lambda *args, **kwargs: calls.append(args))
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
