import sys
import os
import subprocess
import shutil
import tempfile
import suricata.update.rule

DATA_DIR = "./tests/tmp"


def run(args):
    subprocess.check_call(args)


def delete(path):
    if os.path.isdir(path):
        shutil.rmtree(path)
    else:
        os.unlink(path)


print("Python executable: %s" % sys.executable)
print("Python version: %s" % str(sys.version))
print("Current directory: %s" % os.getcwd())

# Override the default source index URL to avoid hitting the network.
os.environ["SOURCE_INDEX_URL"] = "file://%s/tests/index.yaml" % (os.getcwd())

os.environ["ETOPEN_URL"] = "file://%s/tests/emerging.rules.tar.gz" % (
    os.getcwd())

if os.path.exists(DATA_DIR):
    delete(DATA_DIR)

common_args = [
    sys.executable,
    "./bin/suricata-update",
    "-D",
    DATA_DIR,
    "-c",
    "./tests/empty",
]

common_update_args = [
    "--no-test",
    "--no-reload",
    "--suricata-conf",
    "./tests/suricata.yaml",
    "--disable-conf",
    "./tests/disable.conf",
    "--enable-conf",
    "./tests/empty",
    "--drop-conf",
    "./tests/empty",
    "--modify-conf",
    "./tests/empty",
]

# Default run with data directory.
run(common_args + common_update_args)
assert (os.path.exists(DATA_DIR))
assert (os.path.exists(os.path.join(DATA_DIR, "update", "cache")))
assert (os.path.exists(os.path.join(DATA_DIR, "rules", "suricata.rules")))

# Default run with data directory and --no-merge
run(common_args + common_update_args + ["--no-merge"])
assert (os.path.exists(DATA_DIR))
assert (os.path.exists(os.path.join(DATA_DIR, "update", "cache")))
assert (os.path.exists(
    os.path.join(DATA_DIR, "rules", "emerging-deleted.rules")))
assert (os.path.exists(
    os.path.join(DATA_DIR, "rules", "emerging-current_events.rules")))

# Still a default run, but set --output to an alternate location."
run(common_args + common_update_args + ["--output", "./tests/tmp/_rules"])
assert (os.path.exists(os.path.join(DATA_DIR, "_rules")))

# Update sources.
run(common_args + ["update-sources"])
assert (os.path.exists(os.path.join(DATA_DIR, "update", "cache",
                                    "index.yaml")))

# Now delete the index and run lists-sources to see if it downloads
# the index.
delete(os.path.join(DATA_DIR, "update", "cache", "index.yaml"))
run(common_args + ["list-sources"])
assert(not os.path.exists(os.path.join(DATA_DIR, "update", "cache", "index.yaml")))

# Enable a source.
run(common_args + ["enable-source", "oisf/trafficid"])
assert (os.path.exists(
    os.path.join(DATA_DIR, "update", "sources", "oisf-trafficid.yaml")))

# Disable the source.
run(common_args + ["disable-source", "oisf/trafficid"])
assert (not os.path.exists(
    os.path.join(DATA_DIR, "update", "sources", "oisf-trafficid.yaml")))
assert (os.path.exists(
    os.path.join(DATA_DIR, "update", "sources",
                 "oisf-trafficid.yaml.disabled")))

# Remove the source.
run(common_args + ["remove-source", "oisf/trafficid"])
assert (not os.path.exists(
    os.path.join(DATA_DIR, "update", "sources",
                 "oisf-trafficid.yaml.disabled")))

# Add a source with a custom header.
run(common_args + [
    "add-source", "--http-header", "Header: NoSpaces",
    "testing-header-nospaces", "file:///doesnotexist"
])

# Add a source with a custom header with spaces in the value
# (https://redmine.openinfosecfoundation.org/issues/4362)
run(common_args + [
    "add-source", "--http-header", "Authorization: Basic dXNlcjE6cGFzc3dvcmQx",
    "testing-header-with-spaces", "file:///doesnotexist"
])


class IntegrationTest:
    def __init__(self, configs={}):
        self.directory = tempfile.mkdtemp(dir=DATA_DIR)
        self.configs = configs
        self.args = []
        self.write_configs()

        if not "update.yaml" in self.configs:
            self.args += ["-c", "./tests/empty"]

    def write_configs(self):
        for config in self.configs:
            config_filename = "%s/%s" % (self.directory, config)
            with open(config_filename, "w") as of:
                of.write(self.configs[config])
            if config == "modify.conf":
                self.args += ["--modify-conf", config_filename]
            elif config == "drop.conf":
                self.args += ["--drop-conf", config_filename]
            elif config == "enable.conf":
                self.args += ["--enable-conf", config_filename]
            elif config == "disable.conf":
                self.args += ["--disable-conf", config_filename]

    def run(self):
        args = [
            sys.executable,
            "./bin/suricata-update",
            "-D",
            self.directory,
            "--no-test",
            "--no-reload",
            "--suricata-conf",
            "./tests/suricata.yaml",
        ] + self.args
        subprocess.check_call(args)
        self.check()
        self.clean()

    def clean(self):
        if self.directory.startswith(DATA_DIR):
            shutil.rmtree(self.directory)

    def check(self):
        pass

    def get_rule_by_sid(self, sid):
        """ Return all rules where the provided substring is found. """
        with open("%s/rules/suricata.rules" % (self.directory)) as inf:
            for line in inf:
                rule = suricata.update.rule.parse(line)
                if rule.sid == sid:
                    return rule
        return None


class MultipleModifyTest(IntegrationTest):

    configs = {
        "modify.conf":
        """
modifysid emerging-exploit.rules "^alert" | "drop"
modifysid * "^drop(.*)noalert(.*)" | "alert${1}noalert${2}"
        """
    }

    def __init__(self):
        IntegrationTest.__init__(self, self.configs)

    def check(self):
        # This rule should have been converted to drop.
        rule1 = self.get_rule_by_sid(2103461)
        assert(rule1.action == "drop")

        # This one should have been converted back to alert.
        rule2 = self.get_rule_by_sid(2023184)
        assert(rule2.action == "alert")

class DropAndModifyTest(IntegrationTest):

    configs = {
        "drop.conf": """
2024029
        """,
        "modify.conf": """
2024029 "ET INFO" "TEST INFO"
        """
    }

    def __init__(self):
        IntegrationTest.__init__(self, self.configs)

    def check(self):
        rule1 = self.get_rule_by_sid(2024029)
        assert(rule1.action == "drop")
        assert(rule1.msg.startswith("TEST INFO"))


MultipleModifyTest().run()
DropAndModifyTest().run()
