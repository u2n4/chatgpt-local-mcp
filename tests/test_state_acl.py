from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import win32file
import win32security

from edge_bridge import broker


class StateACLTests(unittest.TestCase):
    def test_installer_supplies_owner_and_protected_permissions_at_creation(self):
        with tempfile.TemporaryDirectory() as parent:
            state = Path(parent) / "state"
            original = win32file.CreateDirectory
            observed = []

            def check_creation(path, attributes):
                descriptor = attributes.SECURITY_DESCRIPTOR
                observed.append(descriptor.GetSecurityDescriptorOwner())
                self.assertTrue(descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED)
                return original(path, attributes)

            with patch.object(win32file, "CreateDirectory", side_effect=check_creation):
                broker.setup_state(state)
            self.assertEqual(observed, [broker.owner_sid()])
            broker.verify_state_path(state)
            self.assertEqual(list(state.iterdir()), [])

    def test_broker_refuses_group_default_owner_before_writing_state(self):
        with tempfile.TemporaryDirectory() as parent:
            state = Path(parent) / "state"
            broker.setup_state(state)
            group = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
            original = broker._token_owner_information

            def group_default(info_class):
                return group if info_class == win32security.TokenOwner else original(info_class)

            with patch.object(broker, "_token_owner_information", side_effect=group_default):
                with self.assertRaises(broker.BridgeError) as error:
                    broker.run_broker(state)
            self.assertEqual(error.exception.code, "STATE_TOKEN_OWNER_MISMATCH")
            self.assertEqual(list(state.iterdir()), [])
