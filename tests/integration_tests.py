import sys
import os
import subprocess
import shutil

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
os.environ["SOURCE_INDEX_URL"] = "file://%s/tests/index.yaml" % (
    os.getcwd())

os.environ["ETOPEN_URL"] = "file://%s/tests/emerging.rules.tar.gz" % (
    os.getcwd())

if os.path.exists(DATA_DIR):
    delete(DATA_DIR)

common_args = [
    "./bin/suricata-update",
    "-D", DATA_DIR,
    "-c", "./tests/empty",
]

common_update_args = [
    "--no-test",
    "--no-reload",
    "--suricata-conf", "./tests/suricata.yaml",
    "--disable-conf", "./tests/disable.conf",
    "--enable-conf", "./tests/empty",
    "--drop-conf", "./tests/empty",
    "--modify-conf", "./tests/empty",
]

# Default run with data directory.
run(common_args + common_update_args)
assert(os.path.exists(DATA_DIR))
assert(os.path.exists(os.path.join(DATA_DIR, "update", "cache")))
assert(os.path.exists(os.path.join(DATA_DIR, "rules", "suricata.rules")))

# Still a default run, but set --output to an alternate location."
run(common_args + common_update_args + ["--output", "./tests/tmp/_rules"])
assert(os.path.exists(os.path.join(DATA_DIR, "_rules")))

# Update sources.
run(common_args + ["update-sources"])
assert(os.path.exists(os.path.join(DATA_DIR, "update", "cache", "index.yaml")))

# Now delete the index and run lists-sources to see if it downloads
# the index.
delete(os.path.join(DATA_DIR, "update", "cache", "index.yaml"))
run(common_args + ["list-sources"])
assert(os.path.exists(os.path.join(DATA_DIR, "update", "cache", "index.yaml")))

# Enable a source.
run(common_args + ["enable-source", "oisf/trafficid"])
assert(os.path.exists(
    os.path.join(DATA_DIR, "update", "sources", "oisf-trafficid.yaml")))

# Disable the source.
run(common_args + ["disable-source", "oisf/trafficid"])
assert(not os.path.exists(
    os.path.join(
        DATA_DIR, "update", "sources", "oisf-trafficid.yaml")))
assert(os.path.exists(
    os.path.join(
        DATA_DIR, "update", "sources", "oisf-trafficid.yaml.disabled")))

# Remove the source.
run(common_args + ["remove-source", "oisf/trafficid"])
assert(not os.path.exists(
    os.path.join(
        DATA_DIR, "update", "sources", "oisf-trafficid.yaml.disabled")))
