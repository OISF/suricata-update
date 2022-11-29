index = {   'sources': {   'et/open': {   'description': 'Proofpoint ET Open is a '
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
                                                 'description': 'If you are '
                                                                'running '
                                                                'Suricata, you '
                                                                'can use the '
                                                                "SSLBL's "
                                                                'Suricata JA3 '
                                                                'FingerprintRuleset '
                                                                'to detect '
                                                                'and/or block '
                                                                'malicious SSL '
                                                                'connections '
                                                                'in your '
                                                                'network based '
                                                                'on the JA3 '
                                                                'fingerprint. '
                                                                'Please note '
                                                                'that your '
                                                                'need Suricata '
                                                                '4.1.0 or '
                                                                'newer in '
                                                                'order to use '
                                                                'the JA3 '
                                                                'fingerprint '
                                                                'ruleset.\n',
                                                 'license': 'Non-Commercial',
                                                 'min-version': '4.1.0',
                                                 'summary': 'Abuse.ch Suricata '
                                                            'JA3 Fingerprint '
                                                            'Ruleset',
                                                 'url': 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules',
                                                 'vendor': 'Abuse.ch'},
                   'sslbl/ssl-fp-blacklist': {   'checksum': False,
                                                 'description': 'The SSL '
                                                                'Blacklist '
                                                                '(SSLBL) is a '
                                                                'project of '
                                                                'abuse.ch with '
                                                                'the goal of '
                                                                'detecting '
                                                                'malicious SSL '
                                                                'connections, '
                                                                'by '
                                                                'identifying '
                                                                'and '
                                                                'blacklisting '
                                                                'SSL '
                                                                'certificates '
                                                                'used by '
                                                                'botnet C&C '
                                                                'servers. In '
                                                                'addition, '
                                                                'SSLBL '
                                                                'identifies '
                                                                'JA3 '
                                                                'fingerprints '
                                                                'that helps '
                                                                'you to detect '
                                                                '& block '
                                                                'malware '
                                                                'botnet C&C '
                                                                'communication '
                                                                'on the TCP '
                                                                'layer.\n',
                                                 'license': 'Non-Commercial',
                                                 'summary': 'Abuse.ch SSL '
                                                            'Blacklist',
                                                 'url': 'https://sslbl.abuse.ch/blacklist/sslblacklist.rules',
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
                                         'url': 'https://raw.githubusercontent.com/travisbgreen/hunting-rules/master/hunting.rules',
                                         'vendor': 'tgreen'}},
    'version': 1}