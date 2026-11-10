"""What a child process is allowed to see, and where the data lives when profiles share a gateway.

Both came from the catalogue review: `npm ls -g`, `pip list` and `docker` inherited the gateway's
whole environment, which holds the model provider's API keys; and `data_dir()` read `HERMES_HOME` from
the environment, which is one process-wide value in a multi-profile gateway.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from patch_sentinel import store
from patch_sentinel.sources import shell


class ChildEnvironment(unittest.TestCase):
    def test_a_provider_key_never_reaches_a_child(self):
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-not-real",
                                          "ANTHROPIC_API_KEY": "sk-ant-not-real"}, clear=False):
            self.assertNotIn("OPENROUTER_API_KEY", shell.child_env())
            self.assertNotIn("ANTHROPIC_API_KEY", shell.child_env())

    def test_the_two_sockets_that_make_it_work_survive(self):
        with mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": "/tmp/agent.sock",
                                          "DOCKER_HOST": "unix:///run/user/1000/docker.sock"},
                             clear=False):
            env = shell.child_env()
            self.assertEqual(env.get("SSH_AUTH_SOCK"), "/tmp/agent.sock",
                             "ssh cannot reach the operator's agent without it")
            self.assertEqual(env.get("DOCKER_HOST"), "unix:///run/user/1000/docker.sock",
                             "rootless docker is addressed through it")

    def test_a_child_really_cannot_read_the_key(self):
        os.environ["PATCH_SENTINEL_LEAK_CHECK"] = "visible-in-parent"
        try:
            code, out = shell.run("printf '%s' \"${PATCH_SENTINEL_LEAK_CHECK:-}\"", timeout=30)
        finally:
            os.environ.pop("PATCH_SENTINEL_LEAK_CHECK", None)
        self.assertEqual(code, 0)
        self.assertEqual(out, "", "the variable arrived in the child process")

    def test_path_is_always_present(self):
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=False):
            self.assertTrue(shell.child_env().get("PATH"))
        with mock.patch.dict(os.environ, {"PATH": ""}, clear=True):
            self.assertTrue(shell.child_env().get("PATH"), "a child with no PATH finds no tool")


class TheOtherCallSites(unittest.TestCase):
    """The reviewer named three more: `docker save`, `ssh-add -L`, and the ssh reachability probe.

    Each spawned a process with the gateway's whole environment. The check is the same one the shell
    test makes: plant a key, call the code, look at what the child would have inherited.
    """

    def capture(self, call):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="ssh-ed25519 AAAA", stderr="")
            with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-not-real"}, clear=False):
                call()
            return run.call_args.kwargs.get("env")

    def test_ssh_add_gets_the_minimal_env(self):
        from patch_sentinel.sources import diagnose
        env = self.capture(diagnose.agent_has_keys) or {}
        self.assertIsNotNone(env, "ssh-add inherited the whole environment")
        self.assertNotIn("OPENROUTER_API_KEY", env)

    def test_the_reachability_probe_gets_it_too(self):
        from patch_sentinel.sources import diagnose
        env = self.capture(lambda: diagnose.diagnose("hermes@10.0.0.9")) or {}
        self.assertIsNotNone(env, "the ssh probe inherited the whole environment")
        self.assertNotIn("OPENROUTER_API_KEY", env)

    def test_docker_save_gets_it_too(self):
        from patch_sentinel.sources import image_db
        target = os.path.join(tempfile.mkdtemp(prefix="ps-save-"), "image.tar")
        env = self.capture(lambda: image_db.save_image("debian:12", None, target, 30)) or {}
        self.assertIsNotNone(env, "docker save inherited the whole environment")
        self.assertNotIn("OPENROUTER_API_KEY", env)


class DataDirPerProfile(unittest.TestCase):
    def tearDown(self):
        store.configure({})
        os.environ.pop("PATCH_SENTINEL_DATA", None)

    def test_the_config_value_wins(self):
        target = tempfile.mkdtemp(prefix="ps-data-")
        store.configure({"data_dir": target})
        self.assertEqual(store.data_dir(), Path(target))

    def test_the_env_override_wins_over_the_config(self):
        target = tempfile.mkdtemp(prefix="ps-env-")
        store.configure({"data_dir": tempfile.mkdtemp(prefix="ps-cfg-")})
        os.environ["PATCH_SENTINEL_DATA"] = target
        self.assertEqual(store.data_dir(), Path(target))

    def test_it_falls_back_to_the_hermes_home_it_is_handed(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            home = Path(tempfile.mkdtemp(prefix="ps-home-"))
            os.environ["HERMES_HOME"] = str(home)
            self.assertEqual(store.hermes_home(), home)
            self.assertEqual(store.data_dir(), home / "patch-sentinel")

    def test_outside_hermes_it_still_answers(self):
        """The portability probe runs this package with no Hermes anywhere: no import error."""
        with mock.patch.dict(os.environ, {"HERMES_HOME": "/tmp/ps-explicit-home"}, clear=True):
            self.assertEqual(store.hermes_home(), Path("/tmp/ps-explicit-home"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
