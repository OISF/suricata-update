index = {   'sources': {   'abuse.ch/feodotracker': {   'checksum': False,
                                                'description': 'The Suricata '
                                                               'Botnet C2 IP '
                                                               'Ruleset '
                                                               'contains '
                                                               'botnet C2s '
                                                               'tracked by\n'
                                                               'Feodo Tracker '
                                                               'and can be '
                                                               'used for both, '
                                                               'Suricata and '
                                                               'Snort open\n'
                                                               'source '
                                                               'IDS/IPS. If '
                                                               'you are '
                                                               'running '
                                                               'Suricata or '
                                                               'Snort, you '
                                                               'can\n'
                                                               'use this '
                                                               'ruleset to '
                                                               'detect and/or '
                                                               'block network '
                                                               'connections\n'
                                                               'towards '
                                                               'hostline '
                                                               'servers (IP '
                                                               'address:port '
                                                               'combination).\n',
                                                'license': 'CC0-1.0',
                                                'summary': 'Abuse.ch Feodo '
                                                           'Tracker Botnet C2 '
                                                           'IP ruleset',
                                                'url': 'https://feodotracker.abuse.ch/downloads/feodotracker.tar.gz',
                                                'vendor': 'Abuse.ch'},
                   'abuse.ch/sslbl-blacklist': {   'checksum': False,
                                                   'description': 'The SSL '
                                                                  'Blacklist '
                                                                  '(SSLBL) is '
                                                                  'a project '
                                                                  'of abuse.ch '
                                                                  'with the '
                                                                  'goal\n'
                                                                  'of '
                                                                  'detecting '
                                                                  'malicious '
                                                                  'SSL '
                                                                  'connections, '
                                                                  'by '
                                                                  'identifying '
                                                                  'and\n'
                                                                  'blacklisting '
                                                                  'SSL '
                                                                  'certificates '
                                                                  'used by '
                                                                  'botnet C&C '
                                                                  'servers. '
                                                                  'In\n'
                                                                  'addition, '
                                                                  'SSLBL '
                                                                  'identifies '
                                                                  'JA3 '
                                                                  'fingerprints '
                                                                  'that helps '
                                                                  'you to\n'
                                                                  'detect & '
                                                                  'block '
                                                                  'malware '
                                                                  'botnet C&C '
                                                                  'communication '
                                                                  'on the TCP\n'
                                                                  'layer.\n',
                                                   'license': 'CC0-1.0',
                                                   'replaces': [   'sslbl/ssl-fp-blacklist'],
                                                   'summary': 'Abuse.ch SSL '
                                                              'Blacklist',
                                                   'url': 'https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.tar.gz',
                                                   'vendor': 'Abuse.ch'},
                   'abuse.ch/sslbl-c2': {   'checksum': False,
                                            'description': 'This ruleset '
                                                           'contains all '
                                                           'botnet '
                                                           'Command&Control '
                                                           'servers (C&Cs)\n'
                                                           'identified by '
                                                           'SSLBL to be '
                                                           'associated with a '
                                                           'blacklisted SSL\n'
                                                           'certificate.\n',
                                            'license': 'CC0-1.0',
                                            'summary': 'Abuse.ch Suricata '
                                                       'Botnet C2 IP Ruleset',
                                            'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.tar.gz',
                                            'vendor': 'Abuse.ch'},
                   'abuse.ch/sslbl-ja3': {   'checksum': False,
                                             'description': 'If you are '
                                                            'running Suricata, '
                                                            'you can use the '
                                                            "SSLBL's Suricata\n"
                                                            'JA3 fingerprint '
                                                            'ruleset to detect '
                                                            'and/or block '
                                                            'malicious SSL\n'
                                                            'connections in '
                                                            'your network '
                                                            'based on the JA3 '
                                                            'fingerprint. '
                                                            'Please\n'
                                                            'note that your '
                                                            'need Suricata '
                                                            '4.1.0 or newer in '
                                                            'order to use the\n'
                                                            'JA3 fingerprint '
                                                            'ruleset.\n',
                                             'license': 'CC0-1.0',
                                             'min-version': '4.1.0',
                                             'replaces': [   'sslbl/ja3-fingerprints'],
                                             'summary': 'Abuse.ch Suricata JA3 '
                                                        'Fingerprint Ruleset',
                                             'url': 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.tar.gz',
                                             'vendor': 'Abuse.ch'},
                   'abuse.ch/urlhaus': {   'checksum': False,
                                           'description': 'URLhaus is a '
                                                          'project from '
                                                          'abuse.ch with the '
                                                          'goal of sharing\n'
                                                          'malicious URLs that '
                                                          'are being used for '
                                                          'malware '
                                                          'distribution.\n',
                                           'license': 'CC0-1.0',
                                           'summary': 'Abuse.ch URLhaus '
                                                      'Suricata Rules',
                                           'url': 'https://urlhaus.abuse.ch/downloads/urlhaus_suricata.tar.gz',
                                           'vendor': 'abuse.ch'},
                   'aleksibovellan/nmap': {   'checksum': False,
                                              'description': 'These detection '
                                                             'rules work by '
                                                             'looking for '
                                                             'specific NMAP\n'
                                                             'packet window '
                                                             'sizes, flags, '
                                                             'port numbers, '
                                                             'and known NMAP\n'
                                                             'timing '
                                                             'intervals.\n',
                                              'homepage': 'https://github.com/aleksibovellan/opnsense-suricata-nmaps',
                                              'license': 'MIT',
                                              'min-version': '7.0.4',
                                              'summary': 'Suricata IDS/IPS '
                                                         'Detection Rules '
                                                         'Against NMAP Scans',
                                              'url': 'https://raw.githubusercontent.com/aleksibovellan/opnsense-suricata-nmaps/main/local.rules',
                                              'vendor': 'aleksibovellan'},
                   'et/open': {   'description': 'Proofpoint ET Open is a '
                                                 'timely and accurate rule set '
                                                 'for detecting and blocking '
                                                 'advanced threats\n',
                                  'license': 'MIT',
                                  'summary': 'Emerging Threats Open Ruleset',
                                  'url': 'https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz',
                                  'vendor': 'Proofpoint'},
                   'et/pro': {   'checksum': False,
                                 'description': 'Proofpoint ET Pro is a timely '
                                                'and accurate rule set for '
                                                'detecting and blocking '
                                                'advanced threats\n',
                                 'license': 'Commercial',
                                 'parameters': {   'secret-code': {   'prompt': 'Emerging '
                                                                                'Threats '
                                                                                'Pro '
                                                                                'access '
                                                                                'code'}},
                                 'replaces': ['et/open'],
                                 'subscribe-url': 'https://www.proofpoint.com/us/threat-insight/et-pro-ruleset',
                                 'summary': 'Emerging Threats Pro Ruleset',
                                 'url': 'https://rules.emergingthreatspro.com/%(secret-code)s/suricata-%(__version__)s/etpro.rules.tar.gz',
                                 'vendor': 'Proofpoint'},
                   'etnetera/aggressive': {   'checksum': False,
                                              'license': 'MIT',
                                              'min-version': '4.0.0',
                                              'summary': 'Etnetera aggressive '
                                                         'IP blacklist',
                                              'url': 'https://security.etnetera.cz/feeds/etn_aggressive.rules',
                                              'vendor': 'Etnetera a.s.'},
                   'malsilo/win-malware': {   'checksum': True,
                                              'description': 'TCP/UDP, DNS and '
                                                             'HTTP Windows '
                                                             'threats '
                                                             'artifacts '
                                                             'observed at '
                                                             'runtime.\n',
                                              'homepage': 'https://raw-data.gitlab.io/post/malsilo_2.1/',
                                              'license': 'MIT',
                                              'min-version': '4.1.0',
                                              'obsolete': 'unmaintained',
                                              'summary': 'Commodity malware '
                                                         'rules',
                                              'url': 'https://malsilo.gitlab.io/feeds/dumps/malsilo.rules.tar.gz',
                                              'vendor': 'malsilo'},
                   'oisf/trafficid': {   'checksum': False,
                                         'license': 'MIT',
                                         'min-version': '4.0.0',
                                         'summary': 'Suricata Traffic ID '
                                                    'ruleset',
                                         'support-url': 'https://redmine.openinfosecfoundation.org/',
                                         'url': 'https://openinfosecfoundation.org/rules/trafficid/trafficid.rules',
                                         'vendor': 'OISF'},
                   'pawpatrules': {   'checksum': False,
                                      'description': 'PAW Patrules ruleset '
                                                     'permit to detect many '
                                                     'events on\n'
                                                     'network. Suspicious '
                                                     'flow, malicious tool, '
                                                     'unsuported and\n'
                                                     'vulnerable system, known '
                                                     'threat actors with '
                                                     'various IOCs,\n'
                                                     'lateral movement, bad '
                                                     'practice, shadow IT... '
                                                     'Rules are\n'
                                                     'frequently updated.\n',
                                      'homepage': 'https://pawpatrules.fr/',
                                      'license': 'CC-BY-SA-4.0',
                                      'min-version': '7.0.3',
                                      'summary': 'PAW Patrules is a collection '
                                                 'of rules for IDPS / NSM '
                                                 'Suricata engine',
                                      'url': 'https://rules.pawpatrules.fr/suricata/paw-patrules.tar.gz',
                                      'vendor': 'pawpatrules'},
                   'ptresearch/attackdetection': {   'description': 'The '
                                                                    'Attack '
                                                                    'Detection '
                                                                    'Team '
                                                                    'searches '
                                                                    'for new '
                                                                    'vulnerabilities '
                                                                    'and '
                                                                    '0-days, '
                                                                    'reproduces '
                                                                    'it and '
                                                                    'creates '
                                                                    'PoC '
                                                                    'exploits '
                                                                    'to '
                                                                    'understand '
                                                                    'how these '
                                                                    'security '
                                                                    'flaws '
                                                                    'work and '
                                                                    'how '
                                                                    'related '
                                                                    'attacks '
                                                                    'can be '
                                                                    'detected '
                                                                    'on the '
                                                                    'network '
                                                                    'layer. '
                                                                    'Additionally, '
                                                                    'we are '
                                                                    'interested '
                                                                    'in '
                                                                    'malware '
                                                                    'and '
                                                                    "hackers' "
                                                                    'TTPs, so '
                                                                    'we '
                                                                    'develop '
                                                                    'Suricata '
                                                                    'rules for '
                                                                    'detecting '
                                                                    'all sorts '
                                                                    'of such '
                                                                    'activities.\n',
                                                     'license': 'Custom',
                                                     'license-url': 'https://raw.githubusercontent.com/ptresearch/AttackDetection/master/LICENSE',
                                                     'obsolete': 'no longer '
                                                                 'exists',
                                                     'summary': 'Positive '
                                                                'Technologies '
                                                                'Attack '
                                                                'Detection '
                                                                'Team ruleset',
                                                     'url': 'https://raw.githubusercontent.com/ptresearch/AttackDetection/master/pt.rules.tar.gz',
                                                     'vendor': 'Positive '
                                                               'Technologies'},
                   'ptrules/open': {   'description': 'PT\xa0Rules, an\xa0'
                                                      'open-source project '
                                                      'focused on\xa0enhancing '
                                                      'network security '
                                                      'through proactive '
                                                      'threat detection. As\xa0'
                                                      'the PT\xa0Expert '
                                                      'Security Center attack '
                                                      'detection team, we\xa0'
                                                      'are a\xa0dedicated '
                                                      'group of\xa0'
                                                      'cybersecurity experts '
                                                      'committed to\xa0improve '
                                                      'network security '
                                                      'through open-source '
                                                      'initiatives.\n',
                                       'homepage': 'https://rules.ptsecurity.com',
                                       'license': 'Custom',
                                       'license-url': 'https://rules.ptsecurity.com/files/LICENSE.txt',
                                       'min-version': '5.0.0',
                                       'summary': 'Positive Technologies Open '
                                                  'Ruleset',
                                       'url': 'https://rules.ptsecurity.com/files/ptopen.rules.tar.gz',
                                       'vendor': 'Positive Technologies'},
                   'scwx/enhanced': {   'description': 'Broad ruleset composed '
                                                       'of malware rules and '
                                                       'other security-related '
                                                       'countermeasures, and '
                                                       'curated by the '
                                                       'Secureworks Counter '
                                                       'Threat Unit research '
                                                       'team.  This ruleset '
                                                       'has been enhanced with '
                                                       'comprehensive and '
                                                       'fully '
                                                       'standard-compliant '
                                                       'BETTER metadata '
                                                       '(https://better-schema.readthedocs.io/).\n',
                                        'license': 'Commercial',
                                        'min-version': '3.0.0',
                                        'parameters': {   'secret-code': {   'prompt': 'Secureworks '
                                                                                       'Threat '
                                                                                       'Intelligence '
                                                                                       'Authentication '
                                                                                       'Token'}},
                                        'subscribe-url': 'https://www.secureworks.com/contact/ '
                                                         '(Please reference '
                                                         'CTU Countermeasures)',
                                        'summary': 'Secureworks '
                                                   'suricata-enhanced ruleset',
                                        'url': 'https://ws.secureworks.com/ti/ruleset/%(secret-code)s/Suricata_suricata-enhanced_latest.tgz',
                                        'vendor': 'Secureworks'},
                   'scwx/malware': {   'description': 'High-fidelity, '
                                                      'high-priority ruleset '
                                                      'composed mainly of '
                                                      'malware-related '
                                                      'countermeasures and '
                                                      'curated by the '
                                                      'Secureworks Counter '
                                                      'Threat Unit research '
                                                      'team.\n',
                                       'license': 'Commercial',
                                       'min-version': '3.0.0',
                                       'parameters': {   'secret-code': {   'prompt': 'Secureworks '
                                                                                      'Threat '
                                                                                      'Intelligence '
                                                                                      'Authentication '
                                                                                      'Token'}},
                                       'subscribe-url': 'https://www.secureworks.com/contact/ '
                                                        '(Please reference CTU '
                                                        'Countermeasures)',
                                       'summary': 'Secureworks '
                                                  'suricata-malware ruleset',
                                       'url': 'https://ws.secureworks.com/ti/ruleset/%(secret-code)s/Suricata_suricata-malware_latest.tgz',
                                       'vendor': 'Secureworks'},
                   'scwx/security': {   'description': 'Broad ruleset composed '
                                                       'of malware rules and '
                                                       'other security-related '
                                                       'countermeasures, and '
                                                       'curated by the '
                                                       'Secureworks Counter '
                                                       'Threat Unit research '
                                                       'team.\n',
                                        'license': 'Commercial',
                                        'min-version': '3.0.0',
                                        'parameters': {   'secret-code': {   'prompt': 'Secureworks '
                                                                                       'Threat '
                                                                                       'Intelligence '
                                                                                       'Authentication '
                                                                                       'Token'}},
                                        'subscribe-url': 'https://www.secureworks.com/contact/ '
                                                         '(Please reference '
                                                         'CTU Countermeasures)',
                                        'summary': 'Secureworks '
                                                   'suricata-security ruleset',
                                        'url': 'https://ws.secureworks.com/ti/ruleset/%(secret-code)s/Suricata_suricata-security_latest.tgz',
                                        'vendor': 'Secureworks'},
                   'sslbl/ja3-fingerprints': {   'checksum': False,
                                                 'deprecated': 'Renamed to '
                                                               'abuse.ch/sslbl-ja3',
                                                 'description': 'If you are '
                                                                'running '
                                                                'Suricata, you '
                                                                'can use the '
                                                                "SSLBL's "
                                                                'Suricata\n'
                                                                'JA3 '
                                                                'fingerprint '
                                                                'ruleset to '
                                                                'detect and/or '
                                                                'block '
                                                                'malicious '
                                                                'SSL\n'
                                                                'connections '
                                                                'in your '
                                                                'network based '
                                                                'on the JA3 '
                                                                'fingerprint. '
                                                                'Please\n'
                                                                'note that '
                                                                'your need '
                                                                'Suricata '
                                                                '4.1.0 or '
                                                                'newer in '
                                                                'order to use '
                                                                'the\n'
                                                                'JA3 '
                                                                'fingerprint '
                                                                'ruleset.\n',
                                                 'license': 'CC0-1.0',
                                                 'min-version': '4.1.0',
                                                 'summary': 'Abuse.ch Suricata '
                                                            'JA3 Fingerprint '
                                                            'Ruleset',
                                                 'url': 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.tar.gz',
                                                 'vendor': 'Abuse.ch'},
                   'sslbl/ssl-fp-blacklist': {   'checksum': False,
                                                 'deprecated': 'Renamed to '
                                                               'abuse.ch/sslbl-blacklist',
                                                 'description': 'The SSL '
                                                                'Blacklist '
                                                                '(SSLBL) is a '
                                                                'project of '
                                                                'abuse.ch with '
                                                                'the goal\n'
                                                                'of detecting '
                                                                'malicious SSL '
                                                                'connections, '
                                                                'by '
                                                                'identifying '
                                                                'and\n'
                                                                'blacklisting '
                                                                'SSL '
                                                                'certificates '
                                                                'used by '
                                                                'botnet C&C '
                                                                'servers. In\n'
                                                                'addition, '
                                                                'SSLBL '
                                                                'identifies '
                                                                'JA3 '
                                                                'fingerprints '
                                                                'that helps '
                                                                'you to\n'
                                                                'detect & '
                                                                'block malware '
                                                                'botnet C&C '
                                                                'communication '
                                                                'on the TCP\n'
                                                                'layer.\n',
                                                 'license': 'CC0-1.0',
                                                 'summary': 'Abuse.ch SSL '
                                                            'Blacklist',
                                                 'url': 'https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.tar.gz',
                                                 'vendor': 'Abuse.ch'},
                   'stamus/lateral': {   'description': 'Suricata ruleset '
                                                        'specifically focused '
                                                        'on detecting lateral\n'
                                                        'movement in Microsoft '
                                                        'Windows environments '
                                                        'by Stamus Networks\n',
                                         'license': 'GPL-3.0-only',
                                         'min-version': '6.0.6',
                                         'summary': 'Lateral movement rules',
                                         'support-url': 'https://discord.com/channels/911231224448712714/911238451842666546',
                                         'url': 'https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz',
                                         'vendor': 'Stamus Networks'},
                   'stamus/nrd-14-open': {   'description': 'Newly Registered '
                                                            'Domains list '
                                                            '(last 14 days) to '
                                                            'match on DNS, TLS '
                                                            'and HTTP '
                                                            'communication.\n'
                                                            'Produced by '
                                                            'Stamus Labs '
                                                            'research team.\n',
                                             'license': 'Commercial',
                                             'min-version': '6.0.0',
                                             'parameters': {   'secret-code': {   'prompt': 'Stamus '
                                                                                            'Networks '
                                                                                            'License '
                                                                                            'code'}},
                                             'subscribe-url': 'https://www.stamus-networks.com/stamus-labs/subscribe-to-threat-intel-feed',
                                             'summary': 'Newly Registered '
                                                        'Domains Open only - '
                                                        '14 day list, complete',
                                             'url': 'https://ti.stamus-networks.io/%(secret-code)s/sti-domains-nrd-14.tar.gz',
                                             'vendor': 'Stamus Networks'},
                   'stamus/nrd-30-open': {   'description': 'Newly Registered '
                                                            'Domains list '
                                                            '(last 30 days) to '
                                                            'match on DNS, TLS '
                                                            'and HTTP '
                                                            'communication.\n'
                                                            'Produced by '
                                                            'Stamus Labs '
                                                            'research team.\n',
                                             'license': 'Commercial',
                                             'min-version': '6.0.0',
                                             'parameters': {   'secret-code': {   'prompt': 'Stamus '
                                                                                            'Networks '
                                                                                            'License '
                                                                                            'code'}},
                                             'subscribe-url': 'https://www.stamus-networks.com/stamus-labs/subscribe-to-threat-intel-feed',
                                             'summary': 'Newly Registered '
                                                        'Domains Open only - '
                                                        '30 day list, complete',
                                             'url': 'https://ti.stamus-networks.io/%(secret-code)s/sti-domains-nrd-30.tar.gz',
                                             'vendor': 'Stamus Networks'},
                   'stamus/nrd-entropy-14-open': {   'description': 'Suspicious '
                                                                    'Newly '
                                                                    'Registered '
                                                                    'Domains '
                                                                    'list with '
                                                                    'high '
                                                                    'entropy '
                                                                    '(last 14 '
                                                                    'days) to '
                                                                    'match on '
                                                                    'DNS, TLS '
                                                                    'and HTTP '
                                                                    'communication.\n'
                                                                    'Produced '
                                                                    'by Stamus '
                                                                    'Labs '
                                                                    'research '
                                                                    'team.\n',
                                                     'license': 'Commercial',
                                                     'min-version': '6.0.0',
                                                     'parameters': {   'secret-code': {   'prompt': 'Stamus '
                                                                                                    'Networks '
                                                                                                    'License '
                                                                                                    'code'}},
                                                     'subscribe-url': 'https://www.stamus-networks.com/stamus-labs/subscribe-to-threat-intel-feed',
                                                     'summary': 'Newly '
                                                                'Registered '
                                                                'Domains Open '
                                                                'only - 14 day '
                                                                'list, high '
                                                                'entropy',
                                                     'url': 'https://ti.stamus-networks.io/%(secret-code)s/sti-domains-entropy-14.tar.gz',
                                                     'vendor': 'Stamus '
                                                               'Networks'},
                   'stamus/nrd-entropy-30-open': {   'description': 'Suspicious '
                                                                    'Newly '
                                                                    'Registered '
                                                                    'Domains '
                                                                    'list with '
                                                                    'high '
                                                                    'entropy '
                                                                    '(last 30 '
                                                                    'days) to '
                                                                    'match on '
                                                                    'DNS, TLS '
                                                                    'and HTTP '
                                                                    'communication.\n'
                                                                    'Produced '
                                                                    'by Stamus '
                                                                    'Labs '
                                                                    'research '
                                                                    'team.\n',
                                                     'license': 'Commercial',
                                                     'min-version': '6.0.0',
                                                     'parameters': {   'secret-code': {   'prompt': 'Stamus '
                                                                                                    'Networks '
                                                                                                    'License '
                                                                                                    'code'}},
                                                     'subscribe-url': 'https://www.stamus-networks.com/stamus-labs/subscribe-to-threat-intel-feed',
                                                     'summary': 'Newly '
                                                                'Registered '
                                                                'Domains Open '
                                                                'only - 30 day '
                                                                'list, high '
                                                                'entropy',
                                                     'url': 'https://ti.stamus-networks.io/%(secret-code)s/sti-domains-entropy-30.tar.gz',
                                                     'vendor': 'Stamus '
                                                               'Networks'},
                   'stamus/nrd-phishing-14-open': {   'description': 'Suspicious '
                                                                     'Newly '
                                                                     'Registered '
                                                                     'Domains '
                                                                     'Phishing '
                                                                     'list '
                                                                     '(last 14 '
                                                                     'days) to '
                                                                     'match on '
                                                                     'DNS, TLS '
                                                                     'and HTTP '
                                                                     'communication.\n'
                                                                     'Produced '
                                                                     'by '
                                                                     'Stamus '
                                                                     'Labs '
                                                                     'research '
                                                                     'team.\n',
                                                      'license': 'Commercial',
                                                      'min-version': '6.0.0',
                                                      'parameters': {   'secret-code': {   'prompt': 'Stamus '
                                                                                                     'Networks '
                                                                                                     'License '
                                                                                                     'code'}},
                                                      'subscribe-url': 'https://www.stamus-networks.com/stamus-labs/subscribe-to-threat-intel-feed',
                                                      'summary': 'Newly '
                                                                 'Registered '
                                                                 'Domains Open '
                                                                 'only - 14 '
                                                                 'day list, '
                                                                 'phishing',
                                                      'url': 'https://ti.stamus-networks.io/%(secret-code)s/sti-domains-phishing-14.tar.gz',
                                                      'vendor': 'Stamus '
                                                                'Networks'},
                   'stamus/nrd-phishing-30-open': {   'description': 'Suspicious '
                                                                     'Newly '
                                                                     'Registered '
                                                                     'Domains '
                                                                     'Phishing '
                                                                     'list '
                                                                     '(last 30 '
                                                                     'days) to '
                                                                     'match on '
                                                                     'DNS, TLS '
                                                                     'and HTTP '
                                                                     'communication.\n'
                                                                     'Produced '
                                                                     'by '
                                                                     'Stamus '
                                                                     'Labs '
                                                                     'research '
                                                                     'team.\n',
                                                      'license': 'Commercial',
                                                      'min-version': '6.0.0',
                                                      'parameters': {   'secret-code': {   'prompt': 'Stamus '
                                                                                                     'Networks '
                                                                                                     'License '
                                                                                                     'code'}},
                                                      'subscribe-url': 'https://www.stamus-networks.com/stamus-labs/subscribe-to-threat-intel-feed',
                                                      'summary': 'Newly '
                                                                 'Registered '
                                                                 'Domains Open '
                                                                 'only - 30 '
                                                                 'day list, '
                                                                 'phishing',
                                                      'url': 'https://ti.stamus-networks.io/%(secret-code)s/sti-domains-phishing-30.tar.gz',
                                                      'vendor': 'Stamus '
                                                                'Networks'},
                   'tgreen/hunting': {   'checksum': False,
                                         'description': 'Heuristic ruleset for '
                                                        'hunting. Focus on '
                                                        'anomaly detection and '
                                                        'showcasing latest '
                                                        'engine features, not '
                                                        'performance.\n',
                                         'license': 'GPLv3',
                                         'min-version': '4.1.0',
                                         'summary': 'Threat hunting rules',
                                         'url': 'https://github.com/travisbgreen/hunting-rules/raw/master/hunting.rules.tar.gz',
                                         'vendor': 'tgreen'}},
    'version': 1}