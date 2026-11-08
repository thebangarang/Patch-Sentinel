"""Small pure functions that decide what an operator reads."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patch_sentinel import tools


class RegistryCause(unittest.TestCase):
    """`…/v2/li` was a rate limit cut mid-URL; the words have to name the cause instead."""

    def test_a_rate_limit_is_named(self):
        text = ("ERROR: unexpected status from HEAD request to https://registry-1.docker.io/v2/library/"
                "caddy/manifests/2-alpine: 429 Too Many Requests")
        self.assertIn("429", tools._registry_cause(text))
        self.assertIn("rate", tools._registry_cause(text))

    def test_a_private_tag_is_named(self):
        self.assertIn("login", tools._registry_cause("HTTP 401 Unauthorized"))

    def test_a_dead_network_is_named(self):
        self.assertIn("did not resolve",
                      tools._registry_cause("<urlopen error [Errno -2] Name or service not known>"))

    def test_a_timeout_is_named(self):
        self.assertIn("timed out", tools._registry_cause("timed out"))

    def test_an_unknown_message_keeps_its_head_and_is_never_mid_url_only(self):
        text = "something odd happened while talking to https://registry.example/v2/x"
        self.assertTrue(tools._registry_cause(text))


if __name__ == "__main__":
    unittest.main()
