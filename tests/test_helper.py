"""Hermetic shell tests: no root, launchd, directory service, or real BPF writes.

The helper copy redirects absolute commands and /dev into a temporary fixture.
Regular fixture files model character devices by changing only the -c predicate;
the Rust tests separately reject real regular files and symlinks as BPF devices.
"""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.devices = self.root / "dev"
        self.devices.mkdir()
        self.log = self.root / "commands"
        fake = self.root / "fake"
        fake.write_text("""#!/bin/sh
name=$1
shift
case "$name" in
 id) [ "${TEST_ID_FAIL:-0}" = 0 ] || exit 1; echo "${TEST_UID-0}" ;;
 sysctl) [ "${TEST_SYSCTL_FAIL:-0}" = 0 ] || exit 1; echo "${TEST_MAX-2}" ;;
 chmod) printf '%s\\n' "$name $*" >> "$TEST_LOG";
    if [ "$1" = -N ] && [ "${TEST_DEVFS:-0}" = 1 ]; then
        echo "chmod: Failed to clear ACL: Operation not supported" >&2
        exit 1
    fi
    [ "$name" != "${TEST_FAIL:-none}" ] || exit 1 ;;
 *) printf '%s\\n' "$name $*" >> "$TEST_LOG";
    [ "$name" != "${TEST_FAIL:-none}" ] || exit 1 ;;
esac
""")
        fake.chmod(0o755)
        script = (ROOT / "scripts/chmod-bpf.sh").read_text()
        for binary in ["/usr/bin/id", "/usr/bin/logger", "/usr/sbin/sysctl", "/usr/sbin/chown", "/bin/chmod"]:
            script = script.replace(binary, f"{shlex.quote(str(fake))} {Path(binary).name}")
        script = script.replace("/dev/bpf", f"{self.devices}/bpf")
        script = script.replace('[ ! -c "$device" ]', '[ ! -f "$device" ]')
        self.script = self.root / "helper.sh"
        self.script.write_text(script)
        self.environment = dict(os.environ, TEST_LOG=str(self.log))

    def run_helper(self, **environment):
        return subprocess.run(["/bin/sh", str(self.script)], env=dict(self.environment, **environment), capture_output=True, text=True)

    def commands(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_configures_only_numbered_devices_with_exact_permissions(self):
        for name in ["bpf0", "bpf1", "bpf1.backup", "bpfconfig"]:
            (self.devices / name).touch()
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.commands()
        paths = f"{self.devices / 'bpf0'} {self.devices / 'bpf1'}"
        self.assertEqual(commands, [f"chown root:access_bpf {paths}", f"chmod 0660 {paths}"])

    def test_devfs_without_acl_support_can_be_configured(self):
        (self.devices / "bpf0").touch()
        (self.devices / "bpf1").touch()
        result = self.run_helper(TEST_DEVFS="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any(line.startswith("chmod 0660 ") for line in self.commands()))

    def test_mode_change_failure_is_not_ignored(self):
        (self.devices / "bpf0").touch()
        (self.devices / "bpf1").touch()
        result = self.run_helper(TEST_DEVFS="1", TEST_FAIL="chmod")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(line.startswith("logger ") for line in self.commands()))

    def test_invalid_sysctl_values_fail_before_mutation(self):
        (self.devices / "bpf0").touch()
        for value in ["0", "-1", "invalid", "", "100000000000000000000"]:
            with self.subTest(value=value):
                result = self.run_helper(TEST_MAX=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("debug.bpf_maxdevices", result.stderr)
        self.assertTrue(all(line.startswith("logger ") for line in self.commands()))

    def test_sysctl_failure_is_not_silently_ignored(self):
        self.assertNotEqual(self.run_helper(TEST_SYSCTL_FAIL="1").returncode, 0)
        self.assertTrue(all(line.startswith("logger ") for line in self.commands()))

    def test_non_root_fails_before_mutation(self):
        (self.devices / "bpf0").touch()
        for value in ["501", "", "invalid"]:
            self.assertNotEqual(self.run_helper(TEST_UID=value).returncode, 0)
        self.assertNotEqual(self.run_helper(TEST_ID_FAIL="1").returncode, 0)
        self.assertTrue(all(line.startswith("logger ") for line in self.commands()))

    def test_missing_devices_fail(self):
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no BPF devices", result.stderr)

    def test_symlinks_are_rejected_before_opening_or_chmod(self):
        (self.devices / "bpf0").symlink_to("/dev/null")
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assertTrue(all(line.startswith("logger ") for line in self.commands()))

    def test_late_invalid_device_is_rejected_before_mutation(self):
        (self.devices / "bpf0").touch()
        (self.devices / "bpf999").symlink_to("/dev/null")
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assertTrue(all(line.startswith("logger ") for line in self.commands()))

    def test_permission_command_failure_stops_the_helper(self):
        (self.devices / "bpf0").touch()
        (self.devices / "bpf1").touch()
        self.assertNotEqual(self.run_helper(TEST_FAIL="chown").returncode, 0)
        commands = self.commands()
        self.assertFalse(any("0660" in line for line in commands))


class WrapperTests(unittest.TestCase):
    def test_wrappers_preserve_arguments_and_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "trusted binary"
            binary.write_text('#!/bin/sh\nprintf "<%s>\\n" "$@"\nexit 17\n')
            binary.chmod(0o755)
            for command in ["install", "uninstall"]:
                result = subprocess.run(["/bin/sh", str(ROOT / f"scripts/{command}.sh"), str(binary), "--dry-run", "name with space"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 17)
                self.assertEqual(result.stdout, f"<{command}>\n<--dry-run>\n<name with space>\n")

    def test_wrappers_reject_relative_binary_paths(self):
        for command in ["install", "uninstall"]:
            result = subprocess.run(["/bin/sh", str(ROOT / f"scripts/{command}.sh"), "chmod-bpf"], capture_output=True)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
