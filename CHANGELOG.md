# Change Log

## unreleased

- Python 3 fixes.

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
