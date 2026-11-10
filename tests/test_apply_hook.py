"""The approval gate: a real `cve_apply` must reach Hermes' prompt, and only a real one.

Reviewer-found hole: `cve_apply` was gated only by a typed host label, and the model supplies that
label itself right after reading it from `cve_scan`. So the one tool that changes a machine could run
in cron with nobody to ask. This hook escalates a real apply to Hermes' own approval gate, which
fails closed where no human is present.

These tests pin the shape Hermes consumes — `{"action": "approve", "message", "rule_key"}` — and the
cases that must NOT escalate, because a hook that asks on every call is a hook people turn off.
"""
import importlib.util
import pathlib
import unittest

# The plugin root is `__init__.py` at the repository root, so it is loaded by path: importing it as a
# name would depend on what the checkout directory happens to be called.
ROOT = pathlib.Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "patch_sentinel_plugin", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(_SPEC)
import sys
sys.modules["patch_sentinel_plugin"] = plugin      # so register()'s relative import resolves
_SPEC.loader.exec_module(plugin)


class ApprovalGate(unittest.TestCase):
    def test_a_real_apply_escalates_with_the_host_named(self):
        answer = plugin.pre_tool_call(tool_name="cve_apply",
                                      args={"host": "webasix", "confirm": "webasix",
                                            "dry_run": False})
        self.assertEqual(answer["action"], "approve")
        self.assertIn("webasix", answer["message"])
        self.assertIn("sudo", answer["message"])
        self.assertTrue(answer["rule_key"].startswith("patch-sentinel:cve_apply"))

    def test_the_allowlist_grain_is_the_host(self):
        first = plugin.pre_tool_call(tool_name="cve_apply", args={"host": "beelink", "dry_run": False})
        second = plugin.pre_tool_call(tool_name="cve_apply", args={"host": "webasix", "dry_run": False})
        self.assertNotEqual(first["rule_key"], second["rule_key"],
                            "allowing one host must not allow every host")

    def test_stringy_false_still_escalates(self):
        for value in ("false", "False", "0", 0, "no", "off"):
            with self.subTest(value=value):
                answer = plugin.pre_tool_call(tool_name="cve_apply",
                                              args={"host": "beelink", "dry_run": value})
                self.assertIsNotNone(answer, f"{value!r} was read as a dry run")

    def test_a_dry_run_does_not_escalate(self):
        # "" and the empty containers are the reviewer's case: falsy, but *not* a "false". They must
        # read as a dry run here and in the tool — otherwise one of the two would act alone.
        for value in (True, "true", None, "", "  ", [], {}, 1, "1", "yes"):
            with self.subTest(dry_run=value):
                self.assertIsNone(plugin.pre_tool_call(tool_name="cve_apply",
                                                       args={"host": "beelink", "dry_run": value}))

    def test_another_tool_is_left_alone(self):
        for name in ("cve_scan", "cve_plan", "read_file", "terminal", ""):
            with self.subTest(tool=name):
                self.assertIsNone(plugin.pre_tool_call(tool_name=name,
                                                       args={"dry_run": False}))

    def test_garbage_never_makes_the_hook_raise(self):
        for args in (None, "not a dict", 42, [], {"host": {"nested": True}, "dry_run": False}):
            with self.subTest(args=args):
                answer = plugin.pre_tool_call(tool_name="cve_apply", args=args)
                # either outcome is acceptable for garbage; raising is not
                self.assertTrue(answer is None or answer.get("action") == "approve", answer)

    def test_the_hook_and_the_tool_ask_the_same_question(self):
        """One definition, two callers — the whole point of the fix.

        The gap was that the hook kept its own list of false-ish spellings while ``cve_apply`` used
        ``bool(dry_run)``, so ``dry_run: ""`` skipped the prompt and still ran sudo. Every value now
        has exactly one answer, and the tool's answer is the inverse of the hook's.
        """
        from patch_sentinel import apply as apply_mod
        values = [None, True, False, 0, 1, 0.0, "false", "False", "  false ", "0", "no", "off",
                  "", "  ", "true", "yes", [], {}, ["false"], {"dry_run": False}]
        for value in values:
            with self.subTest(dry_run=value):
                real = apply_mod.is_real_apply(value)
                self.assertEqual(plugin._is_real_apply(value), real,
                                 "the hook disagrees with the definition")
                if isinstance(value, str) and not value.strip():
                    self.assertFalse(real, "a blank string must be a dry run")
                if isinstance(value, (list, dict)):
                    self.assertFalse(real, "a container is not a \"false\"")

    def test_the_tool_resolves_dry_run_from_that_same_function(self):
        import inspect
        from patch_sentinel import tools
        source = inspect.getsource(tools.cve_apply)
        self.assertIn("apply_mod.is_real_apply", source,
                      "cve_apply must not re-derive what a real apply is")
        self.assertNotIn("bool(dry_run)", source,
                         "bool() is what let an empty string through the gate")

    def test_a_deferred_bridge_call_escalates_too(self):
        """The path that got past the gate on 2026-11-10.

        The model called `tool_call` with `cve_apply` inside; Hermes fires `pre_tool_call` for the
        bridge name, so a hook that only matched "cve_apply" never saw it and a real apply ran with no
        prompt. The gate follows the call, not the wrapper.
        """
        answer = plugin.pre_tool_call(tool_name="tool_call", args={"calls": [
            {"name": "cve_apply", "arguments": {"host": "beelink", "confirm": "beelink",
                                                "dry_run": False}}]})
        self.assertIsNotNone(answer, "a bridged real apply went through with no prompt")
        self.assertEqual(answer["action"], "approve")
        self.assertIn("beelink", answer["message"])

    def test_a_bridged_dry_run_stays_quiet(self):
        for inner in ({"host": "beelink", "confirm": "beelink"},
                      {"host": "beelink", "confirm": "beelink", "dry_run": True},
                      {"host": "beelink", "confirm": "beelink", "dry_run": ""}):
            with self.subTest(inner=inner):
                self.assertIsNone(plugin.pre_tool_call(
                    tool_name="tool_call", args={"calls": [{"name": "cve_apply",
                                                            "arguments": inner}]}))

    def test_a_bridge_of_other_tools_is_left_alone(self):
        answer = plugin.pre_tool_call(tool_name="tool_call", args={"calls": [
            {"name": "cve_scan", "arguments": {"host": "beelink"}},
            {"name": "terminal", "arguments": {"command": "ls"}}]})
        self.assertIsNone(answer)

    def test_one_real_call_in_a_batch_is_enough(self):
        answer = plugin.pre_tool_call(tool_name="tool_call", args={"calls": [
            {"name": "cve_scan", "arguments": {"host": "beelink"}},
            {"name": "cve_apply", "arguments": {"host": "webasix", "confirm": "webasix",
                                                "dry_run": False}}]})
        self.assertIsNotNone(answer)
        self.assertIn("webasix", answer["message"], "the prompt must name the host that would change")

    def test_a_malformed_bridge_never_raises(self):
        for bad in ("not a list", [None, 3, "cve_apply"], [{"name": "cve_apply"}],
                    [{"name": "cve_apply", "arguments": "nope"}]):
            with self.subTest(calls=bad):
                plugin.pre_tool_call(tool_name="tool_call", args={"calls": bad})

    def test_the_hook_is_declared_and_registered(self):
        import yaml
        manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text())
        self.assertIn("pre_tool_call", manifest.get("provides_hooks") or [],
                      "the catalogue validates declared hooks against what register() adds")

        calls = {}

        class Context:
            def get_config(self, key, default=None):
                return default

            def register_tool(self, **kwargs):
                calls.setdefault("tools", []).append(kwargs["name"])

            def register_hook(self, name, callback):
                calls.setdefault("hooks", []).append((name, callback))

        plugin.register(Context())
        self.assertIn(("pre_tool_call", plugin.pre_tool_call), calls.get("hooks") or [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
