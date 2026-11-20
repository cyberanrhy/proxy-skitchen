import os
import unittest
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication

from proxy_skitchen.single_instance import (
    SingleInstance,
    activate_existing,
    instance_name,
)

_APP = QCoreApplication.instance() or QCoreApplication([])


def _fresh_name():
    return f"ps-test-{uuid.uuid4().hex[:10]}"


class TestInstanceName(unittest.TestCase):
    def test_name_is_stable_and_prefixed(self):
        self.assertEqual(instance_name(), instance_name())
        self.assertTrue(instance_name().startswith("proxy-skitchen-"))

    def test_name_is_per_user_suffix(self):
        self.assertGreater(len(instance_name()), len("proxy-skitchen-"))


class TestSingleInstance(unittest.TestCase):
    def test_second_acquire_fails(self):
        name = _fresh_name()
        first = SingleInstance(name)
        second = SingleInstance(name)
        try:
            self.assertTrue(first.acquire())
            self.assertFalse(second.acquire())
        finally:
            second.release()
            first.release()

    def test_acquire_is_idempotent(self):
        name = _fresh_name()
        guard = SingleInstance(name)
        try:
            self.assertTrue(guard.acquire())
            self.assertTrue(guard.acquire())
        finally:
            guard.release()

    def test_release_frees_the_name(self):
        name = _fresh_name()
        first = SingleInstance(name)
        self.assertTrue(first.acquire())
        first.release()
        second = SingleInstance(name)
        try:
            self.assertTrue(second.acquire())
        finally:
            second.release()

    def test_second_launch_wakes_the_first(self):
        name = _fresh_name()
        first = SingleInstance(name)
        fired = []
        first.activated.connect(lambda: fired.append(True))
        try:
            self.assertTrue(first.acquire())
            self.assertTrue(activate_existing(name))
            # The server queue is pumped by the running application loop.
            for _ in range(50):
                _APP.processEvents()
                if fired:
                    break
            self.assertTrue(fired, "existing instance was not activated")
        finally:
            first.release()

    def test_activation_without_server_returns_false(self):
        self.assertFalse(activate_existing(_fresh_name(), timeout_ms=300))


if __name__ == "__main__":
    unittest.main()
