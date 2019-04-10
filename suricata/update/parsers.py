import argparse
from suricata.update import commands
from suricata.update import config
def parse_args():
    default_update_yaml = config.DEFAULT_UPDATE_YAML_PATH

    global_parser = argparse.ArgumentParser(add_help=False)
    global_parser.add_argument(
        "-v", "--verbose", action="store_true", default=None,
        help="Be more verbose")
    global_parser.add_argument(
        "-q", "--quiet", action="store_true", default=None,
        help="Be quiet, warning and error messages only")
    global_parser.add_argument(
        "-D", "--data-dir", metavar="<directory>", dest="data_dir",
        help="Data directory (default: /var/lib/suricata)")
    global_parser.add_argument(
        "-c", "--config", metavar="<filename>",
        help="configuration file (default: %s)" %(default_update_yaml))
    global_parser.add_argument(
        "--suricata-conf", metavar="<filename>",
        help="configuration file (default: /etc/suricata/suricata.yaml)")
    global_parser.add_argument(
        "--suricata", metavar="<path>",
        help="Path to Suricata program")
    global_parser.add_argument(
        "--suricata-version", metavar="<version>",
        help="Override Suricata version")
    global_parser.add_argument(
        "--user-agent", metavar="<user-agent>",
        help="Set custom user-agent string")
    global_parser.add_argument(
        "--no-check-certificate", action="store_true", default=None,
        help="Disable server SSL/TLS certificate verification")
    global_parser.add_argument(
        "-V", "--version", action="store_true", default=False,
        help="Display version")

    global_args, rem = global_parser.parse_known_args()

    if global_args.version:
        revision_string = " (rev: %s)" % (revision) if revision else ""
        print("suricata-update version {}{}".format(version, revision_string))
        return 0

    if not rem or rem[0].startswith("-"):
        rem.insert(0, "update")

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="subcommand", metavar="<command>")

    # The "update" (default) sub-command parser.
    update_parser = subparsers.add_parser(
        "update", add_help=True, parents=[global_parser],
        formatter_class=argparse.RawDescriptionHelpFormatter)

    update_parser.add_argument(
        "-o", "--output", metavar="<directory>", dest="output",
        help="Directory to write rules to")
    update_parser.add_argument("-f", "--force", action="store_true",
                               default=False,
                               help="Force operations that might otherwise be skipped")
    update_parser.add_argument("--yaml-fragment", metavar="<filename>",
                               help="Output YAML fragment for rule inclusion")
    update_parser.add_argument("--url", metavar="<url>", action="append",
                               default=[],
                               help="URL to use instead of auto-generating one (can be specified multiple times)")
    update_parser.add_argument("--local", metavar="<path>", action="append",
                               default=[],
                               help="Local rule files or directories (can be specified multiple times)")
    update_parser.add_argument("--sid-msg-map", metavar="<filename>",
                               help="Generate a sid-msg.map file")
    update_parser.add_argument("--sid-msg-map-2", metavar="<filename>",
                               help="Generate a v2 sid-msg.map file")

    update_parser.add_argument("--disable-conf", metavar="<filename>",
                               help="Filename of rule disable filters")
    update_parser.add_argument("--enable-conf", metavar="<filename>",
                               help="Filename of rule enable filters")
    update_parser.add_argument("--modify-conf", metavar="<filename>",
                               help="Filename of rule modification filters")
    update_parser.add_argument("--drop-conf", metavar="<filename>",
                               help="Filename of drop rules filters")

    update_parser.add_argument("--ignore", metavar="<pattern>", action="append",
                               default=None,
                               help="Filenames to ignore (can be specified multiple times; default: *deleted.rules)")
    update_parser.add_argument("--no-ignore", action="store_true",
                               default=False,
                               help="Disables the ignore option.")

    update_parser.add_argument("--threshold-in", metavar="<filename>",
                               help="Filename of rule thresholding configuration")
    update_parser.add_argument("--threshold-out", metavar="<filename>",
                               help="Output of processed threshold configuration")

    update_parser.add_argument("--dump-sample-configs", action="store_true",
                               default=False,
                               help="Dump sample config files to current directory")
    update_parser.add_argument("--etopen", action="store_true",
                               help="Use ET-Open rules (default)")
    update_parser.add_argument("--reload-command", metavar="<command>",
                               help="Command to run after update if modified")
    update_parser.add_argument("--no-reload", action="store_true", default=False,
                               help="Disable reload")
    update_parser.add_argument("-T", "--test-command", metavar="<command>",
                               help="Command to test Suricata configuration")
    update_parser.add_argument("--no-test", action="store_true", default=False,
                               help="Disable testing rules with Suricata")

    update_parser.add_argument("--no-merge", action="store_true", default=False,
                               help="Do not merge the rules into a single file")

    # Hidden argument, --now to bypass the timebased bypass of
    # updating a ruleset.
    update_parser.add_argument(
        "--now", default=False, action="store_true", help=argparse.SUPPRESS)

    update_parser.epilog = r"""other commands:
    update-sources             Update the source index
    list-sources               List available sources
    enable-source              Enable a source from the index
    disable-source             Disable an enabled source
    remove-source              Remove an enabled or disabled source
    list-enabled-sources       List all enabled sources
    add-source                 Add a new source by URL
"""

    # The Python 2.7 argparse module does prefix matching which can be
    # undesirable. Reserve some names here that would match existing
    # options to prevent prefix matching.
    update_parser.add_argument("--disable", default=False,
                               help=argparse.SUPPRESS)
    update_parser.add_argument("--enable", default=False,
                               help=argparse.SUPPRESS)
    update_parser.add_argument("--modify", default=False,
                               help=argparse.SUPPRESS)
    update_parser.add_argument("--drop", default=False, help=argparse.SUPPRESS)

    commands.listsources.register(subparsers.add_parser(
        "list-sources", parents=[global_parser]))
    commands.listenabledsources.register(subparsers.add_parser(
        "list-enabled-sources", parents=[global_parser]))
    commands.addsource.register(subparsers.add_parser(
        "add-source", parents=[global_parser]))
    commands.updatesources.register(subparsers.add_parser(
        "update-sources", parents=[global_parser]))
    commands.enablesource.register(subparsers.add_parser(
        "enable-source", parents=[global_parser]))
    commands.disablesource.register(subparsers.add_parser(
        "disable-source", parents=[global_parser]))
    commands.removesource.register(subparsers.add_parser(
        "remove-source", parents=[global_parser]))

    args = parser.parse_args(rem)

    # Merge global args into args.
    for arg in vars(global_args):
        if not hasattr(args, arg):
            setattr(args, arg, getattr(global_args, arg))
        elif hasattr(args, arg) and getattr(args, arg) is None:
            setattr(args, arg, getattr(global_args, arg))

    return args
