# Change Log

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
