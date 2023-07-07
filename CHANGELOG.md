# Change Log

## 1.3.0 - 2023-07-07

- Fix loading of configuration files specified in update.yaml:
  https://redmine.openinfosecfoundation.org/issues/6172

## 1.3.0-rc1 - 2022-01-30
- Be consistent about warning about old index. The index won't be
  automatically updated now in some cases and not in others. Instead
  opt to never auto-update:
  https://redmine.openinfosecfoundation.org/issues/3249
- Better flowbit resolution logging in verbose mode
  https://redmine.openinfosecfoundation.org/issues/3205
- Hide advanced command line options from help output:
  https://redmine.openinfosecfoundation.org/issues/3974
- Allow spaces in custom HTTP headers. Redmine issue
  https://redmine.openinfosecfoundation.org/issues/4362
- Better error message on invalid source specification:
  https://redmine.openinfosecfoundation.org/issues/5141

## 1.2.7 - 2022-01-30
- Embed an index that has been formatted so diffs are more readable.
- Documentation update with respect to how Suricata-Update is bundled
  with all versions of Suricata now.

## 1.2.6 - 2022-11-25
- Allow checksum URL to be specified by the index:
  https://redmine.openinfosecfoundation.org/issues/5684
- Metadata rule matching for disable, enable and drop:
  https://redmine.openinfosecfoundation.org/issues/5561

## 1.2.5 - 2022-09-22
- Update entrypoint search path when not installed with distutils. This is
  required for installation when bundled with Suricata 6.0.7 or newer:
  https://redmine.openinfosecfoundation.org/issues/5313

## 1.2.4 - 2022-04-19
- Fix multiple modifications to a rule:
  https://redmine.openinfosecfoundation.org/issues/4259
- Fix "check-versions" where the running Suricata is newer than what the index
  knows about: https://redmine.openinfosecfoundation.org/issues/4373
- Fix issue with dataset handling. Also adds file renaming to avoid conflicts:
  https://redmine.openinfosecfoundation.org/issues/5010.
- New modify option to add metadata:
  https://redmine.openinfosecfoundation.org/issues/5221.
- Respect Suricata's sysconfdir when loading configuration files:
  https://redmine.openinfosecfoundation.org/issues/4374.
- Modify rule to add metadata:
  https://redmine.openinfosecfoundation.org/issues/5221
- Don't fail when source removed from index:
  https://redmine.openinfosecfoundation.org/issues/5269
- Option fail on download error:
  https://redmine.openinfosecfoundation.org/issues/4579

## 1.2.3 - 2021-11-05
- Allow more custom characters in custom http header to allow for more
  of the base64 character set:
  https://redmine.openinfosecfoundation.org/issues/4701
- Send custom HTTP headers with check for remote checksum file:
  https://redmine.openinfosecfoundation.org/issues/4001

## 1.2.2 - 2021-05-18
- Fix "no-test" when set in configuration file:
  https://redmine.openinfosecfoundation.org/issues/4493

## 1.2.1 - 2021-02-23
- Fix --no-merge. Redmine issue
  https://redmine.openinfosecfoundation.org/issues/4324.

## 1.2.0 - 2020-10-05
- Documentation updates.

## 1.2.0rc2 - 2020-09-09

### Features
- Obsolete and deprecated source handling from the index:
  https://redmine.openinfosecfoundation.org/issues/3918,
  https://redmine.openinfosecfoundation.org/issues/3919.

### Fixes
- Fix re-enabling a disabled source that was initially added with
  "add-source": https://redmine.openinfosecfoundation.org/issues/3843
- Handle duplicate filenames across multiple sources:
  https://redmine.openinfosecfoundation.org/issues/3174

## 1.2.0rc1 - 2020-08-05

### Added
- Add summary for update-sources command:
  https://redmine.openinfosecfoundation.org/issues/2472
- Disable SMB rules if installed Suricata does not support them:
  https://redmine.openinfosecfoundation.org/issues/3280
- Better error on bad modify filter:
  https://redmine.openinfosecfoundation.org/issues/3536
- Missing documentation for list-sources, list-enabled-sources and
  check-versions:
  https://redmine.openinfosecfoundation.org/issues/3228
- Optimization for modify filters:
  https://redmine.openinfosecfoundation.org/issues/3620
- Fix --http-header option. Header was not being sent:
  https://redmine.openinfosecfoundation.org/issues/3696
- Add classification.config management. Suricata-Update will now load
  the Suricata installed classification.config and merge it with
  classification.config's found in rule
  files. https://redmine.openinfosecfoundation.org/issues/3203
- Copy md5/sha1/sha256 file lists from rulesets into the rule output
  directory: https://redmine.openinfosecfoundation.org/issues/2688
- Copy dataset files from ruleset into the rule output directory:
  https://redmine.openinfosecfoundation.org/issues/3528

## 1.1.0 - 2019-10-11
- Disable ja3 rules if the Suricata build or runtime configuration
  does not support
  ja3. https://redmine.openinfosecfoundation.org/issues/3215
- New command, check-versions to compare the version of Suricata on
  the system to Suricata version information in the index. Can let you
  know if Suricata is
  outdated. https://redmine.openinfosecfoundation.org/issues/2341

## 1.1.0rc1 - 2019-09-09
- Enable integration tests on
  Travis-CI. https://redmine.openinfosecfoundation.org/issues/2760
- Fix error on missing sid, or missing ';' in rule
  parsing. https://redmine.openinfosecfoundation.org/issues/2867
- Improve permission errors from tracebacks to more user friendly
  error messages. https://redmine.openinfosecfoundation.org/issues/2875
- Log warnings and errors to stderr, info and debug to stdout.
  https://redmine.openinfosecfoundation.org/issues/2565
- Cleaner exit on CTRL-C.
  https://redmine.openinfosecfoundation.org/issues/2878
- Run offline.
  https://redmine.openinfosecfoundation.org/issues/2864
- Log warning on duplicate SID.
  https://redmine.openinfosecfoundation.org/issues/2879
- Parse rule files alphabetically.
  https://redmine.openinfosecfoundation.org/issues/2892
- Set the noalert option on rules enabled for flowbit dependencies.
  https://redmine.openinfosecfoundation.org/issues/2906
- Allow sources to be specified without a checksum URL to prevent the
  warning log message when this URL does not
  exist. https://redmine.openinfosecfoundation.org/issues/3100

## 1.0.5 - 2019-04-26
- Fix NULL pointer dereference (FORWARD_NULL) found by
  Coverity. https://redmine.openinfosecfoundation.org/issues/2834
- Add a download connection timeout of 30
  seconds. https://redmine.openinfosecfoundation.org/issues/2703
- Fix issue with --no-merge command line
  option. https://redmine.openinfosecfoundation.org/issues/2869
- Fix handling of default ignore
  files. https://redmine.openinfosecfoundation.org/issues/2851
- Allow repeated calls to enable the same rule source without exiting
  with an error. https://redmine.openinfosecfoundation.org/issues/2728

## 1.0.4 - 2019-03-07
- Enable integration tests on
  Travis-CI. https://redmine.openinfosecfoundation.org/issues/2760
- Reduce memory usage. https://redmine.openinfosecfoundation.org/issues/2791

## 1.0.3 - 2018-12-21
- Fix enable-source command.
  https://redmine.openinfosecfoundation.org/issues/2753

## 1.0.2 - 2018-12-18
- Fix installs on older versions of Python 2.7.
  https://redmine.openinfosecfoundation.org/issues/2747

## 1.0.1 - 2018-12-16
- Add --free argument to list-sources command to show only those
  that are freely
  available. https://redmine.openinfosecfoundation.org/issues/2641
- If user-agent is configured to be empty, don't send the header at
  all. This also fixes an issue where trying to set the user agent to
  an empty string reset it back to the
  default. https://redmine.openinfosecfoundation.org/issues/2665
- Fix --dump-sample-configs. The data files were being
  installed. https://redmine.openinfosecfoundation.org/issues/2683
- When installing with pip, make pyyaml and a required dependency so
  it will be installed automatically if needed. This does not apply
  when installed bundled with
  Suricata. https://redmine.openinfosecfoundation.org/issues/2667
- Fix missing check for None, from
  Coverity. https://redmine.openinfosecfoundation.org/issues/2676
- Suppress download progress meter when not on a
  tty. https://redmine.openinfosecfoundation.org/issues/2743
- Hide git revision if not available in --version.
- Update list of engine provided rules to include.
- Allow a custom HTTP header to be set on a source when added with
  add-source. https://redmine.openinfosecfoundation.org/issues/2577

## 1.0.0 - 2018-11-05
- Fix failure to run custom test
  command. https://redmine.openinfosecfoundation.org/issues/2652

## 1.0.0rc2 - 2018-10-12
- Python 3 fix for enable-source.
  https://redmine.openinfosecfoundation.org/issues/2549
- Fix interactive input for add-source command.
  https://redmine.openinfosecfoundation.org/issues/2550
- Python fix for loading disable.conf (and other files).
  https://redmine.openinfosecfoundation.org/issues/2551

## 1.0.0rc1 - 2018-07-17
- Python 3 fixes.
- Bundle a copy of the index which can be used if download source for
  the index is not available, and no index was previously
  downloaded. Warnings will be issued.
- Fix for Python versions prior to 2.7.9 that don't have
  ssl.create_default_context. For example, Ubuntu Trusty.
- Fix exception while referencing configuration
  filename. https://redmine.openinfosecfoundation.org/issues/2526

## 1.0.0b1 - 2018-01-19
- Various fixes for Python 3.
- Allow the default state directory of /var/lib/suricata to be changed
  with the command line parameter -D (--data-dir). Fixes issue
  https://redmine.openinfosecfoundation.org/issues/2334.
- Cache directory is now /var/lib/suricata/update/cache (or
  update/cache under configured data directory).
- list-sources: If no index is found, automatically run
  update-sources. Fixes issue
  https://redmine.openinfosecfoundation.org/issues/2336.
- New testing framework, integration tests and a docker test with the
  focus of testing on more versions of Python.
- Allow a custom HTTP User-Agent to be set
  (https://redmine.openinfosecfoundation.org/issues/2344).
- Command line option and configuration parameter to set the
  suricata.yaml configuration file used
  (https://redmine.openinfosecfoundation.org/issues/2350).
- Allow the Suricata application to be set in the configuration file.
- Allow disabling of TLS certificate validation
  (--no-check-certificate).
- Safe loading of YAML files
  (https://redmine.openinfosecfoundation.org/issues/2359)

## 1.0.0a1 - 2017-12-05
- Initial alpha release of Suricata-Update. A Suricata rule update tool
  based on idstools-rulecat, relicensed under the GPLv2 with copyright
  assigned to the OISF.
- Features are derived from idstools-rulecat, but with more
  opinionated defaults.
- Supports an index of rule sources to aid in discovery of rulesets.
