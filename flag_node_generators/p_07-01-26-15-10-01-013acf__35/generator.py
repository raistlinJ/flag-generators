import argparse
import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any


GENERATOR_FAMILY = "service_variant_runtime"


VARIANTS: dict[str, dict[str, Any]] = {'cache_cdn_manifest_cache': {'auth': 'none',
                              'default_port': 18081,
                              'endpoint': '/manifests/release.json',
                              'files': {'README.txt': 'Stale edge cache export for release '
                                                      'troubleshooting.\n',
                                        'manifests/release.json': '{"release":"{digest}","asset":"recover.txt","flag":"{flag}"}\n'},
                              'flag_path': 'manifests/release.json',
                              'pack': 'cache',
                              'protocol': 'http',
                              'service': 'cdn-cache',
                              'title': 'CDN Manifest Cache'},
 'cache_memcached_feature_flags': {'auth': 'none',
                                   'default_port': 11211,
                                   'endpoint': '/cache/feature_flags',
                                   'extra_facts': {'ExposedSecret(service)': 'memcached_feature_flags'},
                                   'files': {'cache/feature_flags.txt': 'VALUE feature_flags 0 96\n'
                                                                        'rollout=true\n'
                                                                        'marker={flag}\n'
                                                                        'END\n',
                                             'cache/stats.txt': 'STAT curr_items 5\n'
                                                                'STAT bytes 4096\n'
                                                                'END\n'},
                                   'flag_path': 'cache/feature_flags.txt',
                                   'pack': 'cache',
                                   'protocol': 'memcached',
                                   'service': 'memcached',
                                   'title': 'Memcached Feature Flags'},
 'cache_redis_acl_tokens': {'auth': 'password',
                            'default_port': 16379,
                            'endpoint': '/keys/acl:admin',
                            'extra_facts': {'ExposedSecret(service)': 'redis_acl_token',
                                            'Token(service)': '{token}'},
                            'files': {'README.txt': 'Redis-style ACL cache export. Authenticate '
                                                    'before reading keys.\n',
                                      'keys/acl_admin.txt': 'acl:admin={flag}\napi_token={token}\n',
                                      'keys/cache_listing.txt': 'acl:admin\n'
                                                                'session:rollout\n'
                                                                'feature:ops\n'},
                            'flag_path': 'keys/acl_admin.txt',
                            'pack': 'cache',
                            'protocol': 'redis',
                            'service': 'redis',
                            'title': 'Redis ACL Token Store',
                            'user_prefix': 'redisacl'},
 'cache_session_replay_store': {'auth': 'none',
                                'default_port': 16379,
                                'endpoint': '/keys/replay:admin',
                                'extra_facts': {'Misconfiguration(service)': 'redis_replay_no_auth'},
                                'files': {'keys/cache_listing.txt': 'replay:guest\n'
                                                                    'replay:admin\n'
                                                                    'checkout:last\n',
                                          'keys/replay_admin.txt': 'replay:admin={"trace":"{digest}","flag":"{flag}"}\n'},
                                'flag_path': 'keys/replay_admin.txt',
                                'pack': 'cache',
                                'protocol': 'redis',
                                'service': 'redis',
                                'title': 'Session Replay Store'},
 'cache_varnish_debug_objects': {'auth': 'none',
                                 'default_port': 18080,
                                 'endpoint': '/objects/debug_headers.txt',
                                 'extra_facts': {'ExposedSecret(service)': 'varnish_debug_cache'},
                                 'files': {'objects/debug_headers.txt': 'GET /admin/status\n'
                                                                        'X-Debug-Trace: {digest}\n'
                                                                        'X-Recovery-Flag: {flag}\n',
                                           'objects/index.txt': 'debug_headers.txt\n'
                                                                'static_manifest.txt\n'},
                                 'flag_path': 'objects/debug_headers.txt',
                                 'pack': 'cache',
                                 'protocol': 'http',
                                 'service': 'varnish',
                                 'title': 'Varnish Debug Objects'},
 'database_mongo_export_documents': {'auth': 'password',
                                     'default_port': 17017,
                                     'endpoint': '/database/incidents.jsonl',
                                     'extra_facts': {'ExposedSecret(service)': 'mongo_incident_export',
                                                     'Version(service)': 'mongo-simulated-6'},
                                     'files': {'database/incidents.jsonl': '{"id":"{digest}","status":"open","recovery":"{flag}"}\n',
                                               'database/users.jsonl': '{"user":"{user}","role":"reader"}\n'},
                                     'flag_path': 'database/incidents.jsonl',
                                     'pack': 'database',
                                     'protocol': 'database',
                                     'service': 'mongo',
                                     'title': 'Mongo Export Documents',
                                     'user_prefix': 'mongoapp'},
 'database_mysql_reports_dump': {'archive_path': 'database/reports-nightly.zip',
                                 'auth': 'password',
                                 'default_port': 13306,
                                 'endpoint': '/database/reports_dump.sql',
                                 'extra_facts': {'BackupArchive(file)': 'database/reports-nightly.zip',
                                                 'Version(service)': 'mysql-8-simulated'},
                                 'files': {'database/reports_dump.sql': 'CREATE TABLE '
                                                                        'quarterly_report(id int, '
                                                                        'marker text);\n'
                                                                        'INSERT INTO '
                                                                        'quarterly_report VALUES '
                                                                        "(7, '{flag}');\n",
                                           'database/restore.log': 'reports restore {digest}: '
                                                                   'verified\n'},
                                 'flag_path': 'database/reports_dump.sql',
                                 'pack': 'database',
                                 'protocol': 'database',
                                 'service': 'mysql',
                                 'title': 'MySQL Reports Dump',
                                 'user_prefix': 'mysql_reports'},
 'database_oracle_wallet_note': {'auth': 'password',
                                 'default_port': 11521,
                                 'endpoint': '/database/wallet_note.txt',
                                 'extra_facts': {'ExposedSecret(service)': 'oracle_wallet_note'},
                                 'files': {'database/tnsnames.ora': 'FIELDDB=(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT={port})))\n',
                                           'database/wallet_note.txt': 'Wallet alias: '
                                                                       'field_{digest}\n'
                                                                       'credential={user}:{password}\n'
                                                                       'flag={flag}\n'},
                                 'flag_path': 'database/wallet_note.txt',
                                 'pack': 'database',
                                 'protocol': 'database',
                                 'service': 'oracle',
                                 'title': 'Oracle Wallet Note',
                                 'user_prefix': 'ora_wallet'},
 'database_postgres_audit_schema': {'auth': 'password',
                                    'default_port': 15432,
                                    'endpoint': '/database/audit_schema.sql',
                                    'extra_facts': {'ExposedSecret(service)': 'postgres_audit_dump',
                                                    'Version(service)': 'postgresql-15-simulated'},
                                    'files': {'database/audit_schema.sql': '-- audit export '
                                                                           '{digest}\n'
                                                                           'INSERT INTO '
                                                                           'audit.notes VALUES '
                                                                           "(42, '{flag}');\n",
                                              'database/schema.sql': 'CREATE SCHEMA audit;\n'
                                                                     'CREATE TABLE audit.notes(id '
                                                                     'int, note text);\n'},
                                    'flag_path': 'database/audit_schema.sql',
                                    'pack': 'database',
                                    'protocol': 'database',
                                    'service': 'postgres',
                                    'title': 'Postgres Audit Schema',
                                    'user_prefix': 'pg_audit'},
 'database_sqlite_backup_file': {'archive_path': 'database/app_backup.zip',
                                 'auth': 'none',
                                 'default_port': 19001,
                                 'endpoint': '/database/app_backup.sql',
                                 'extra_facts': {'BackupArchive(file)': 'database/app_backup.zip'},
                                 'files': {'database/README.txt': 'SQLite backup exported for '
                                                                  'field diagnostics.\n',
                                           'database/app_backup.sql': 'CREATE TABLE notes(key '
                                                                      'text, value text);\n'
                                                                      'INSERT INTO notes VALUES '
                                                                      "('recovery', '{flag}');\n"},
                                 'flag_path': 'database/app_backup.sql',
                                 'pack': 'database',
                                 'protocol': 'database',
                                 'service': 'sqlite',
                                 'title': 'SQLite Backup File'},
 'dns_delegation_glue_hint': {'auth': 'none',
                              'default_port': 1053,
                              'endpoint': '/AXFR/delegated.lab.example',
                              'extra_facts': {'Hostname(host)': 'ns1.delegated.lab.example'},
                              'files': {'zones/delegated.lab.example.zone': '$ORIGIN '
                                                                            'delegated.lab.example.\n'
                                                                            '@ IN NS ns1\n'
                                                                            'ns1 IN A 10.20.30.40\n'
                                                                            'operator-note IN TXT '
                                                                            '"{flag}"\n'},
                              'flag_path': 'zones/delegated.lab.example.zone',
                              'pack': 'dns',
                              'protocol': 'dns',
                              'service': 'dns',
                              'title': 'Delegation Glue Hint'},
 'dns_dkim_selector_secret': {'auth': 'none',
                              'default_port': 1053,
                              'endpoint': '/TXT/selector1._domainkey.mail.lab.example',
                              'extra_facts': {'ExposedSecret(service)': 'dns_dkim_comment',
                                              'Hostname(host)': 'selector1._domainkey.mail.lab.example'},
                              'files': {'records/selector1._domainkey.mail.lab.example.txt': 'selector1._domainkey.mail.lab.example '
                                                                                             'TXT '
                                                                                             '"v=DKIM1; '
                                                                                             'k=rsa; '
                                                                                             'p=MIIB; '
                                                                                             'note={flag}"\n'},
                              'flag_path': 'records/selector1._domainkey.mail.lab.example.txt',
                              'pack': 'dns',
                              'protocol': 'dns',
                              'service': 'dns',
                              'title': 'DKIM Selector Secret'},
 'dns_reverse_zone_note': {'auth': 'none',
                           'default_port': 1053,
                           'endpoint': '/AXFR/20.10.in-addr.arpa',
                           'extra_facts': {'Hostname(host)': 'jumpbox.internal.lab',
                                           'Misconfiguration(service)': 'dns_reverse_zone_note'},
                           'files': {'zones/20.10.in-addr.arpa.zone': '$ORIGIN '
                                                                      '20.10.in-addr.arpa.\n'
                                                                      '15 IN PTR '
                                                                      'jumpbox.internal.lab.\n'
                                                                      '15-note IN TXT "{flag}"\n'},
                           'flag_path': 'zones/20.10.in-addr.arpa.zone',
                           'pack': 'dns',
                           'protocol': 'dns',
                           'service': 'dns',
                           'title': 'Reverse Zone Note'},
 'dns_split_horizon_txt': {'auth': 'none',
                           'default_port': 1053,
                           'endpoint': '/TXT/internal-split.lab.example',
                           'extra_facts': {'ExposedSecret(service)': 'dns_split_txt',
                                           'Hostname(host)': 'internal-split.lab.example'},
                           'files': {'records/internal-split.lab.example.txt': 'internal-split.lab.example '
                                                                               'TXT '
                                                                               '"flag={flag}"\n',
                                     'zones/internal.lab.zone': '$ORIGIN internal.lab.example.\n'
                                                                'internal-split 60 IN TXT '
                                                                '"flag={flag}"\n'},
                           'flag_path': 'records/internal-split.lab.example.txt',
                           'pack': 'dns',
                           'protocol': 'dns',
                           'service': 'dns',
                           'title': 'Split Horizon TXT'},
 'dns_srv_admin_endpoint': {'auth': 'none',
                            'default_port': 1053,
                            'endpoint': '/AXFR/admin.lab.example',
                            'extra_facts': {'Hostname(host)': '_admin._tcp.admin.lab.example',
                                            'Misconfiguration(service)': 'dns_srv_leak'},
                            'files': {'zones/admin.lab.example.zone': '$ORIGIN admin.lab.example.\n'
                                                                      '_admin._tcp 60 IN SRV 0 5 '
                                                                      '{port} admin01\n'
                                                                      'admin-note 60 IN TXT '
                                                                      '"{flag}"\n'},
                            'flag_path': 'zones/admin.lab.example.zone',
                            'pack': 'dns',
                            'protocol': 'dns',
                            'service': 'dns',
                            'title': 'SRV Admin Endpoint'},
 'dns_txt_secret_record': {'auth': 'none',
                           'default_port': 1053,
                           'endpoint': '/TXT/vault.internal.example.test',
                           'extra_facts': {'ExposedSecret(service)': 'dns_txt_record',
                                           'Hostname(host)': 'vault.internal.example.test'},
                           'files': {'records/helpdesk.internal.example.test.txt': 'helpdesk.internal.example.test '
                                                                                   'TXT '
                                                                                   '"owner=support"\n',
                                     'records/vault.internal.example.test.txt': 'vault.internal.example.test '
                                                                                'TXT '
                                                                                '"recovery={flag}"\n'},
                           'flag_path': 'records/vault.internal.example.test.txt',
                           'pack': 'dns',
                           'protocol': 'dns',
                           'service': 'dns',
                           'title': 'DNS TXT Secret Record'},
 'dns_zone_transfer_records': {'auth': 'none',
                               'default_port': 1053,
                               'endpoint': '/AXFR/internal.example.test',
                               'extra_facts': {'Hostname(host)': 'internal.example.test',
                                               'Misconfiguration(service)': 'dns_zone_transfer'},
                               'files': {'zones/README.txt': 'Zone transfer allowed from lab '
                                                             'networks for diagnostics.\n',
                                         'zones/internal.example.test.zone': '$ORIGIN '
                                                                             'internal.example.test.\n'
                                                                             '@ 3600 IN SOA ns1 '
                                                                             'hostmaster 1 7200 '
                                                                             '3600 1209600 3600\n'
                                                                             'flag 60 IN TXT '
                                                                             '"{flag}"\n'
                                                                             'files 60 IN A '
                                                                             '10.10.20.15\n'},
                               'flag_path': 'zones/internal.example.test.zone',
                               'pack': 'dns',
                               'protocol': 'dns',
                               'service': 'dns',
                               'title': 'Leaky Internal DNS Zone'},
 'ftp_anonymous_finance_drop': {'auth': 'anonymous',
                                'default_port': 2121,
                                'endpoint': '/finance/q2-close.txt',
                                'extra_facts': {'ExposedSecret(service)': 'ftp_public_drop',
                                                'Misconfiguration(service)': 'anonymous_ftp'},
                                'files': {'README.txt': 'Anonymous FTP mirror for finance handoff '
                                                        'files.\n',
                                          'finance/q2-close.txt': 'Q2 close packet {digest}\n'
                                                                  'flag={flag}\n',
                                          'finance/vendor-aging.csv': 'vendor,days_open,owner\n'
                                                                      'Northwind,45,ap\n'
                                                                      'Contoso,12,ops\n'},
                                'flag_path': 'finance/q2-close.txt',
                                'pack': 'ftp',
                                'protocol': 'ftp',
                                'service': 'ftp',
                                'title': 'Finance FTP Drop'},
 'ftp_user_backup_home': {'archive_path': 'backups/restore-bundle.zip',
                          'auth': 'password',
                          'default_port': 2121,
                          'endpoint': '/backups/restore-note.txt',
                          'extra_facts': {'BackupArchive(file)': 'backups/restore-bundle.zip'},
                          'files': {'README.txt': 'Nightly backup landing area. Authenticated '
                                                  'access is required.\n',
                                    'backups/index.tsv': 'snapshot\tstatus\n'
                                                         'core-router\tcomplete\n'
                                                         'finance-share\twarning\n',
                                    'backups/restore-note.txt': 'Restore batch {digest}\n'
                                                                'flag={flag}\n'},
                          'flag_path': 'backups/restore-note.txt',
                          'pack': 'ftp',
                          'protocol': 'ftp',
                          'service': 'ftp',
                          'title': 'Authenticated Backup FTP',
                          'user_prefix': 'backupftp'},
 'git_deploy_key_repo': {'api_key': True,
                         'auth': 'password',
                         'default_port': 19418,
                         'endpoint': '/repo/deploy.env',
                         'extra_facts': {'APIKey(service)': '{api_key}',
                                         'SourceCode(repo)': 'deploy_repo'},
                         'files': {'repo/README.md': '# Deploy repo\n'
                                                     'Restricted release automation mirror.\n',
                                   'repo/deploy.env': 'DEPLOY_API_KEY={api_key}\n'
                                                      'RECOVERY_FLAG={flag}\n'},
                         'flag_path': 'repo/deploy.env',
                         'pack': 'git',
                         'protocol': 'git',
                         'service': 'git',
                         'title': 'Deploy Key Repository',
                         'user_prefix': 'gitdeploy'},
 'git_http_bare_repo': {'auth': 'none',
                        'default_port': 19418,
                        'endpoint': '/repo/config',
                        'extra_facts': {'ExposedSecret(service)': 'git_config_secret',
                                        'SourceCode(repo)': 'ops_mirror'},
                        'files': {'repo/HEAD': 'ref: refs/heads/main\n',
                                  'repo/config': '[core]\n'
                                                 '\trepositoryformatversion = 0\n'
                                                 '[remote "origin"]\n'
                                                 '\turl = ssh://git@example.invalid/ops.git\n'
                                                 '[secret]\n'
                                                 '\tflag = {flag}\n',
                                  'repo/refs/heads/main': '{digest}\n'},
                        'flag_path': 'repo/config',
                        'pack': 'git',
                        'protocol': 'git',
                        'service': 'git',
                        'title': 'Bare Git Repository Mirror'},
 'imap_shared_mailbox': {'auth': 'password',
                         'default_port': 2143,
                         'endpoint': '/INBOX/0004.eml',
                         'files': {'INBOX/0001.eml': 'From: helpdesk@example.invalid\n'
                                                     'Subject: onboarding\n'
                                                     '\n'
                                                     'Welcome to the shared mailbox.\n',
                                   'INBOX/0004.eml': 'From: facilities@example.invalid\n'
                                                     'Subject: mailbox handoff\n'
                                                     '\n'
                                                     'Shared mailbox note {digest}\n'
                                                     'flag={flag}\n'},
                         'flag_path': 'INBOX/0004.eml',
                         'pack': 'mail',
                         'protocol': 'imap',
                         'service': 'imap',
                         'title': 'Shared IMAP Mailbox',
                         'user_prefix': 'mailbox'},
 'ldap_anonymous_directory': {'auth': 'anonymous',
                              'default_port': 1389,
                              'endpoint': '/ou=People,dc=lab,dc=local',
                              'extra_facts': {'Misconfiguration(service)': 'ldap_anonymous_bind'},
                              'files': {'directory/groups.ldif': 'dn: '
                                                                 'cn=operators,ou=Groups,dc=lab,dc=local\n'
                                                                 'memberUid: svc-backup\n',
                                        'directory/people.ldif': 'dn: '
                                                                 'uid=svc-backup,ou=People,dc=lab,dc=local\n'
                                                                 'cn: Backup Service\n'
                                                                 'description: {flag}\n'},
                              'flag_path': 'directory/people.ldif',
                              'pack': 'ldap',
                              'protocol': 'ldap',
                              'service': 'ldap',
                              'title': 'Anonymous LDAP Directory'},
 'ldap_bind_service_account': {'auth': 'password',
                               'default_port': 1389,
                               'endpoint': '/cn=service-notes,dc=lab,dc=local',
                               'extra_facts': {'ExposedSecret(service)': 'ldap_service_account'},
                               'files': {'directory/access.ldif': 'dn: cn=readers,dc=lab,dc=local\n'
                                                                  'member: '
                                                                  'uid={user},ou=People,dc=lab,dc=local\n',
                                         'directory/service-notes.ldif': 'dn: '
                                                                         'cn=service-notes,dc=lab,dc=local\n'
                                                                         'cn: service-notes\n'
                                                                         'description: bind '
                                                                         'recovered {flag}\n'},
                               'flag_path': 'directory/service-notes.ldif',
                               'pack': 'ldap',
                               'protocol': 'ldap',
                               'service': 'ldap',
                               'title': 'LDAP Service Account Bind',
                               'user_prefix': 'svc_ldap'},
 'mail_dmarc_report_queue': {'auth': 'none',
                             'default_port': 2526,
                             'endpoint': '/reports/dmarc-aggregate.xml',
                             'extra_facts': {'ExposedSecret(service)': 'dmarc_report_note'},
                             'files': {'reports/README.txt': 'Aggregate reports queued for analyst '
                                                             'review.\n',
                                       'reports/dmarc-aggregate.xml': '<feedback><report_id>{digest}</report_id><forensic>{flag}</forensic></feedback>\n'},
                             'flag_path': 'reports/dmarc-aggregate.xml',
                             'pack': 'mail',
                             'protocol': 'mail',
                             'service': 'dmarc',
                             'title': 'DMARC Report Queue'},
 'mail_imap_archive_mailbox': {'auth': 'password',
                               'default_port': 2143,
                               'endpoint': '/Archive/0042.eml',
                               'extra_facts': {'ExposedSecret(service)': 'imap_archived_message'},
                               'files': {'Archive/0042.eml': 'From: records@example.invalid\n'
                                                             'Subject: archive handoff {digest}\n'
                                                             '\n'
                                                             'flag={flag}\n',
                                         'INBOX/0001.eml': 'From: helpdesk@example.invalid\n'
                                                           'Subject: welcome\n'
                                                           '\n'
                                                           'Mailbox ready.\n'},
                               'flag_path': 'Archive/0042.eml',
                               'pack': 'mail',
                               'protocol': 'imap',
                               'service': 'imap',
                               'title': 'IMAP Archive Mailbox',
                               'user_prefix': 'imap_archive'},
 'mail_pop3_shared_dropbox': {'auth': 'password',
                              'default_port': 2110,
                              'endpoint': '/dropbox/0007.eml',
                              'extra_facts': {'ExposedSecret(service)': 'pop3_dropbox_message'},
                              'files': {'dropbox/0007.eml': 'From: vendor@example.invalid\n'
                                                            'Subject: pickup code\n'
                                                            '\n'
                                                            'Pickup marker {flag}\n',
                                        'dropbox/index.txt': '0007.eml\n0002.eml\n'},
                              'flag_path': 'dropbox/0007.eml',
                              'pack': 'mail',
                              'protocol': 'mail',
                              'service': 'pop3',
                              'title': 'POP3 Shared Dropbox',
                              'user_prefix': 'popdrop'},
 'mail_smtp_bounce_spool': {'auth': 'none',
                            'default_port': 2525,
                            'endpoint': '/spool/bounce-2401.eml',
                            'extra_facts': {'Misconfiguration(service)': 'smtp_spool_readable'},
                            'files': {'spool/README.txt': 'Deferred and bounced messages are '
                                                          'exposed in this fixture.\n',
                                      'spool/bounce-2401.eml': 'From: '
                                                               'MAILER-DAEMON@example.invalid\n'
                                                               'Subject: delivery failed {digest}\n'
                                                               '\n'
                                                               'Diagnostic-Code: {flag}\n'},
                            'flag_path': 'spool/bounce-2401.eml',
                            'pack': 'mail',
                            'protocol': 'smtp',
                            'service': 'smtp',
                            'title': 'SMTP Bounce Spool'},
 'mail_webmail_export_attachment': {'auth': 'password',
                                    'default_port': 18082,
                                    'endpoint': '/exports/attachment_note.txt',
                                    'files': {'exports/attachment_note.txt': 'Attachment export '
                                                                             '{digest}\n'
                                                                             'owner={user}\n'
                                                                             'flag={flag}\n',
                                              'exports/mailbox_index.csv': 'id,subject\n'
                                                                           '7,attachment note\n'},
                                    'flag_path': 'exports/attachment_note.txt',
                                    'pack': 'mail',
                                    'protocol': 'http',
                                    'service': 'webmail',
                                    'title': 'Webmail Export Attachment',
                                    'user_prefix': 'webmail'},
 'memcached_session_cache': {'auth': 'none',
                             'default_port': 11211,
                             'endpoint': '/cache/session_admin',
                             'extra_facts': {'ExposedSecret(service)': 'memcached_session'},
                             'files': {'cache/session_admin.txt': 'VALUE session_admin 0 64\n'
                                                                  '{flag}\n'
                                                                  'END\n',
                                       'cache/stats.txt': 'STAT curr_items 3\n'
                                                          'STAT bytes 2048\n'
                                                          'END\n'},
                             'flag_path': 'cache/session_admin.txt',
                             'pack': 'cache',
                             'protocol': 'memcached',
                             'service': 'memcached',
                             'title': 'Memcached Session Cache'},
 'mqtt_credentialed_ops_topic': {'auth': 'password',
                                 'default_port': 1883,
                                 'endpoint': '/topics/ops/private',
                                 'files': {'topics/ops_private.txt': 'topic=ops/private\n'
                                                                     'message=dispatch window '
                                                                     '{digest}\n'
                                                                     'flag={flag}\n',
                                           'topics/site_public.txt': 'topic=site/public\n'
                                                                     'message=ok\n'},
                                 'flag_path': 'topics/ops_private.txt',
                                 'pack': 'mqtt',
                                 'protocol': 'mqtt',
                                 'service': 'mqtt',
                                 'title': 'Credentialed MQTT Ops Topic',
                                 'user_prefix': 'mqttops'},
 'mqtt_public_broker_topic': {'auth': 'none',
                              'default_port': 1883,
                              'endpoint': '/topics/site/alerts',
                              'extra_facts': {'Misconfiguration(service)': 'mqtt_public_topic',
                                              'Token(service)': '{token}'},
                              'files': {'topics/README.txt': 'Use SUB site/alerts in the lab '
                                                             'service shell.\n',
                                        'topics/site_alerts.txt': 'topic=site/alerts\n'
                                                                  'message=maintenance token '
                                                                  '{token}\n'
                                                                  'flag={flag}\n'},
                              'flag_path': 'topics/site_alerts.txt',
                              'pack': 'mqtt',
                              'protocol': 'mqtt',
                              'service': 'mqtt',
                              'title': 'Public MQTT Topic',
                              'token': True},
 'mysql_backup_table': {'archive_path': 'database/mysql-nightly.zip',
                        'auth': 'password',
                        'default_port': 13306,
                        'endpoint': '/database/backup_table.sql',
                        'extra_facts': {'BackupArchive(file)': 'database/mysql-nightly.zip',
                                        'Version(service)': 'mysql-8-simulated'},
                        'files': {'database/backup_table.sql': 'CREATE TABLE backup_notes(id int, '
                                                               'note text);\n'
                                                               'INSERT INTO backup_notes VALUES '
                                                               "(1, '{flag}');\n",
                                  'database/restore.log': 'restore id {digest}: finished with '
                                                          'warnings\n'},
                        'flag_path': 'database/backup_table.sql',
                        'pack': 'database',
                        'protocol': 'database',
                        'service': 'mysql',
                        'title': 'MySQL Backup Table',
                        'user_prefix': 'mysqlapp'},
 'postgres_customer_dump': {'auth': 'password',
                            'default_port': 15432,
                            'endpoint': '/database/customer_exports.sql',
                            'extra_facts': {'ExposedSecret(service)': 'postgres_dump',
                                            'Version(service)': 'postgresql-15-simulated'},
                            'files': {'database/customer_exports.sql': '-- exported by support '
                                                                       'desk {digest}\n'
                                                                       'INSERT INTO notes VALUES '
                                                                       "('priority', '{flag}');\n",
                                      'database/schema.sql': 'CREATE TABLE notes (name text, value '
                                                             'text);\n'
                                                             'CREATE TABLE customers (id int, name '
                                                             'text);\n'},
                            'flag_path': 'database/customer_exports.sql',
                            'pack': 'database',
                            'protocol': 'database',
                            'service': 'postgres',
                            'title': 'Postgres Customer Dump',
                            'user_prefix': 'pgapp'},
 'redis_exposed_keys': {'auth': 'none',
                        'default_port': 16379,
                        'endpoint': '/keys/session:admin',
                        'extra_facts': {'Misconfiguration(service)': 'redis_no_auth',
                                        'Token(service)': '{token}'},
                        'files': {'keys/cache_listing.txt': 'session:admin\n'
                                                            'feature:beta\n'
                                                            'queue:rollout\n',
                                  'keys/session_admin.txt': 'session:admin={flag}\n'
                                                            'reset_token={token}\n'},
                        'flag_path': 'keys/session_admin.txt',
                        'pack': 'cache',
                        'protocol': 'redis',
                        'service': 'redis',
                        'title': 'Exposed Redis Cache',
                        'token': True},
 'smb_engineering_build_drop': {'auth': 'guest',
                                'default_port': 1445,
                                'endpoint': '/Builds/release-note.txt',
                                'extra_facts': {'Misconfiguration(service)': 'smb_guest_build_drop'},
                                'files': {'Builds/checksums.txt': 'release-note.txt  pending\n',
                                          'Builds/release-note.txt': 'Build train {digest}\n'
                                                                     'release marker {flag}\n'},
                                'flag_path': 'Builds/release-note.txt',
                                'pack': 'smb',
                                'protocol': 'smb',
                                'service': 'smb',
                                'title': 'Engineering Build Drop'},
 'smb_finance_quarterly_share': {'auth': 'password',
                                 'default_port': 1445,
                                 'endpoint': '/Finance/quarterly-close.txt',
                                 'extra_facts': {'ExposedSecret(service)': 'smb_finance_share'},
                                 'files': {'Finance/quarterly-close.txt': 'Quarterly close packet '
                                                                          '{digest}\n'
                                                                          'flag={flag}\n',
                                           'Finance/vendors.csv': 'vendor,amount\nContoso,4200\n'},
                                 'flag_path': 'Finance/quarterly-close.txt',
                                 'pack': 'smb',
                                 'protocol': 'smb',
                                 'service': 'smb',
                                 'title': 'Finance Quarterly Share',
                                 'user_prefix': 'finshare'},
 'smb_guest_public_share': {'auth': 'guest',
                            'default_port': 1445,
                            'endpoint': '/Public/ops-note.txt',
                            'extra_facts': {'Misconfiguration(service)': 'smb_guest_share'},
                            'files': {'Public/ops-note.txt': 'Shared operations note {digest}\n'
                                                             'flag={flag}\n',
                                      'Public/roster.csv': 'team,contact\n'
                                                           'field,field@example.invalid\n'
                                                           'platform,platform@example.invalid\n',
                                      'README.txt': 'Guest-readable department share.\n'},
                            'flag_path': 'Public/ops-note.txt',
                            'pack': 'smb',
                            'protocol': 'smb',
                            'service': 'smb',
                            'title': 'Guest SMB Share'},
 'smb_hr_payroll_share': {'auth': 'password',
                          'default_port': 1445,
                          'endpoint': '/HR/payroll-exception.txt',
                          'extra_facts': {'ExposedSecret(service)': 'smb_payroll_share'},
                          'files': {'HR/onboarding/checklist.md': '# New hire checklist\n'
                                                                  '- badge\n'
                                                                  '- payroll\n'
                                                                  '- device\n',
                                    'HR/payroll-exception.txt': 'Payroll exception report '
                                                                '{digest}\n'
                                                                'flag={flag}\n'},
                          'flag_path': 'HR/payroll-exception.txt',
                          'pack': 'smb',
                          'protocol': 'smb',
                          'service': 'smb',
                          'title': 'HR Payroll Share',
                          'user_prefix': 'hrshare'},
 'smb_it_scripts_share': {'auth': 'password',
                          'default_port': 1445,
                          'endpoint': '/Scripts/deploy.ps1',
                          'extra_facts': {'ExposedSecret(service)': 'smb_scripts_share'},
                          'files': {'Scripts/README.txt': 'Shared deployment scripts for IT '
                                                          'operations.\n',
                                    'Scripts/deploy.ps1': '$Marker = "{flag}"\n'
                                                          'Write-Output "Deploy trace {digest}"\n'},
                          'flag_path': 'Scripts/deploy.ps1',
                          'pack': 'smb',
                          'protocol': 'smb',
                          'service': 'smb',
                          'title': 'IT Scripts Share',
                          'user_prefix': 'itshare'},
 'smb_legal_case_archive': {'auth': 'password',
                            'default_port': 1445,
                            'endpoint': '/Legal/case-summary.txt',
                            'extra_facts': {'ExposedSecret(service)': 'smb_legal_archive'},
                            'files': {'Legal/case-summary.txt': 'Case summary {digest}\n'
                                                                'restricted marker={flag}\n',
                                      'Legal/index.txt': 'case-summary.txt\nhold-notice.txt\n'},
                            'flag_path': 'Legal/case-summary.txt',
                            'pack': 'smb',
                            'protocol': 'smb',
                            'service': 'smb',
                            'title': 'Legal Case Archive',
                            'user_prefix': 'legalshare'},
 'smb_public_scanner_share': {'auth': 'guest',
                              'default_port': 1445,
                              'endpoint': '/Scans/device-inventory.txt',
                              'extra_facts': {'Misconfiguration(service)': 'smb_public_scanner_share'},
                              'files': {'Scans/README.txt': 'Scanner appliance dumps jobs here for '
                                                            'pickup.\n',
                                        'Scans/device-inventory.txt': 'device,owner,marker\n'
                                                                      'core-router,netops,{flag}\n'},
                              'flag_path': 'Scans/device-inventory.txt',
                              'pack': 'smb',
                              'protocol': 'smb',
                              'service': 'smb',
                              'title': 'Public Scanner Share'},
 'smtp_open_relay_queue': {'auth': 'none',
                           'default_port': 2525,
                           'endpoint': '/queue/deferred-1729.eml',
                           'extra_facts': {'Misconfiguration(service)': 'smtp_open_relay'},
                           'files': {'queue/README.txt': 'Deferred queue is world-readable in this '
                                                         'lab fixture.\n',
                                     'queue/deferred-1729.eml': 'From: noc@example.invalid\n'
                                                                'To: ops@example.invalid\n'
                                                                'Subject: relay exception '
                                                                '{digest}\n'
                                                                '\n'
                                                                '{flag}\n'},
                           'flag_path': 'queue/deferred-1729.eml',
                           'pack': 'mail',
                           'protocol': 'smtp',
                           'service': 'smtp',
                           'title': 'SMTP Relay Queue'}}

def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:
        return {}


def _write_text(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def _digest(*parts: str, length: int = 16) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()[:length]


def _flag(seed: str, node_name: str, variant_id: str, prefix: str) -> str:
    clean_prefix = (prefix or "FLAG").strip() or "FLAG"
    return f"{clean_prefix}{{{_digest(seed, node_name, variant_id, length=20)}}}"


def _format_template(value: Any, mapping: dict[str, Any]) -> str:
    text = str(value)
    for key, replacement in mapping.items():
        text = text.replace("{" + str(key) + "}", str(replacement))
    return text


def _parse_credential(raw: Any) -> tuple[str, str] | None:
    text = str(raw or "").strip()
    if not text:
        return None
    if ":" not in text:
        raise ValueError('Credential(user, password) must use "user:password" format')
    user, password = text.split(":", 1)
    user = user.strip()
    password = password.strip()
    if not user or not password:
        raise ValueError("Credential(user, password) must include both user and password")
    return user, password


def _int_range(value: Any, default: int, *, name: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value if value is not None and str(value).strip() != "" else default)
    except Exception as exc:
        raise ValueError(f"invalid {name}: {value}") from exc
    if number < minimum or number > maximum:
        raise ValueError(f"invalid {name}: {number}")
    return number


def _service_script() -> str:
    return r'''#!/usr/bin/env python3
import json
import os
import socketserver
from pathlib import Path


ROOT = Path(os.environ.get("SERVICE_ROOT", "/srv/service")).resolve()
CONFIG = json.loads((ROOT / "config.json").read_text("utf-8"))


def _safe_path(raw):
    rel = str(raw or "").strip().replace("\\", "/").lstrip("/")
    if not rel:
        return None
    candidate = (ROOT / rel).resolve()
    try:
        candidate.relative_to(ROOT)
    except Exception:
        return None
    if not candidate.exists() or not candidate.is_file():
        return None
    return candidate


def _read_rel(raw):
    path = _safe_path(raw)
    if path is None:
        return "ERR not found\n"
    return path.read_text("utf-8", errors="replace")


def _listing():
    rows = []
    for path in sorted(ROOT.rglob("*")):
        if path.name == "config.json" or not path.is_file():
            continue
        rows.append(str(path.relative_to(ROOT)).replace("\\", "/"))
    return "\n".join(rows) + ("\n" if rows else "")


class Handler(socketserver.StreamRequestHandler):
    def setup(self):
        super().setup()
        self.authed = CONFIG.get("auth") in ("none", "anonymous", "guest")

    def write(self, text):
        self.wfile.write(str(text).encode("utf-8", "replace"))

    def _check_auth(self):
        if self.authed:
            return True
        self.write("ERR authentication required\n")
        return False

    def _auth(self, parts):
        if CONFIG.get("auth") in ("none", "anonymous", "guest"):
            self.authed = True
            self.write("OK anonymous access\n")
            return
        if len(parts) >= 3 and parts[1] == CONFIG.get("username") and parts[2] == CONFIG.get("password"):
            self.authed = True
            self.write("OK authenticated\n")
            return
        self.write("ERR invalid credentials\n")

    def _http_get(self, line):
        try:
            path = line.split()[1].split("?", 1)[0].lstrip("/") or "README.txt"
        except Exception:
            path = "README.txt"
        body = _read_rel(path)
        status = "200 OK" if not body.startswith("ERR ") else "404 Not Found"
        response = f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {len(body.encode('utf-8'))}\r\n\r\n{body}"
        self.write(response)

    def _protocol_alias(self, raw, upper):
        protocol = CONFIG.get("protocol")
        parts = raw.split()
        if protocol == "ftp":
            if upper.startswith("USER "):
                self.write("331 password required\n")
                return True
            if upper.startswith("PASS "):
                if CONFIG.get("auth") == "password":
                    expected = CONFIG.get("password")
                    self.authed = raw.split(None, 1)[1].strip() == expected if len(parts) > 1 else False
                else:
                    self.authed = True
                self.write("230 login ok\n" if self.authed else "530 login incorrect\n")
                return True
            if upper == "LIST":
                if self._check_auth():
                    self.write(_listing())
                return True
            if upper.startswith("RETR "):
                if self._check_auth():
                    self.write(_read_rel(raw.split(None, 1)[1]))
                return True
        if protocol == "smb" and upper in ("SHARES", "DIR"):
            if self._check_auth():
                self.write(_listing())
            return True
        if protocol == "dns":
            if upper.startswith("AXFR") or upper.startswith("TXT"):
                self.write(_read_rel(CONFIG.get("flag_path")))
                return True
        if protocol == "redis":
            if upper.startswith("KEYS"):
                self.write(_listing())
                return True
            if upper.startswith("GET "):
                self.write(_read_rel(raw.split(None, 1)[1].replace(":", "_") + ".txt"))
                return True
        if protocol == "memcached":
            if upper == "STATS":
                self.write(_read_rel("cache/stats.txt"))
                return True
            if upper.startswith("GET "):
                self.write(_read_rel("cache/" + raw.split(None, 1)[1] + ".txt"))
                return True
        if protocol == "smtp":
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                self.write("250-coretg relay\n250 HELP\n")
                return True
            if upper.startswith("VRFY") or upper == "QUEUE":
                self.write(_read_rel(CONFIG.get("flag_path")))
                return True
        if protocol == "imap":
            if upper.startswith("LOGIN"):
                if len(parts) >= 3 and parts[1] == CONFIG.get("username") and parts[2] == CONFIG.get("password"):
                    self.authed = True
                    self.write("OK LOGIN completed\n")
                else:
                    self.write("NO LOGIN failed\n")
                return True
            if upper.startswith("FETCH"):
                if self._check_auth():
                    self.write(_read_rel(CONFIG.get("flag_path")))
                return True
        if protocol == "ldap":
            if upper.startswith("BIND"):
                self._auth(["AUTH"] + parts[1:])
                return True
            if upper.startswith("SEARCH"):
                if self._check_auth():
                    self.write(_read_rel(CONFIG.get("flag_path")))
                return True
        if protocol == "mqtt":
            if upper.startswith("SUB"):
                if self._check_auth():
                    self.write(_read_rel(CONFIG.get("flag_path")))
                return True
        return False

    def handle(self):
        self.write(CONFIG.get("banner", "service ready") + "\n")
        self.write("Commands: HELP, INFO, AUTH <user> <password>, LIST, GET <path>\n")
        while True:
            line = self.rfile.readline(4096)
            if not line:
                return
            raw = line.decode("utf-8", "replace").strip()
            if not raw:
                continue
            upper = raw.upper()
            if raw.startswith("GET ") and " HTTP/" in raw:
                self._http_get(raw)
                return
            parts = raw.split()
            if upper in ("QUIT", "EXIT"):
                self.write("bye\n")
                return
            if upper == "HELP":
                self.write(CONFIG.get("help", "Use LIST and GET <path>.\n"))
                continue
            if upper == "INFO":
                self.write(json.dumps({k: CONFIG.get(k) for k in ("variant_id", "service", "protocol", "title", "endpoint")}, indent=2) + "\n")
                continue
            if upper.startswith("AUTH "):
                self._auth(parts)
                continue
            if self._protocol_alias(raw, upper):
                continue
            if upper == "LIST":
                if self._check_auth():
                    self.write(_listing())
                continue
            if upper.startswith("GET "):
                if self._check_auth():
                    self.write(_read_rel(raw.split(None, 1)[1]))
                continue
            self.write("ERR unknown command\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(os.environ.get("SERVICE_PORT", str(CONFIG.get("port", 9000))))
    with Server(("0.0.0.0", port), Handler) as server:
        server.serve_forever()
'''


def _challenge_dockerfile(port: int) -> str:
    return (
        "FROM python:3.11-slim\n"
        "WORKDIR /srv\n"
        "COPY service.py /srv/service.py\n"
        "COPY service /srv/service\n"
        f"ENV SERVICE_PORT={port}\n"
        f"EXPOSE {port}\n"
        "CMD [\"python\", \"/srv/service.py\"]\n"
    )


def _compose(port: int, hostname: str) -> str:
    return (
        "services:\n"
        "  node:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile\n"
        "    environment:\n"
        f"      SERVICE_PORT: {json.dumps(str(port))}\n"
        "    ports:\n"
        f"      - \"{port}:{port}\"\n"
        f"    hostname: {hostname}\n"
    )


def _write_archive(service_root: Path, archive_rel: str, mapping: dict[str, Any]) -> None:
    archive_path = service_root / archive_rel
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", _format_template("Recovery archive {digest}\n", mapping))
        archive.writestr("secrets/recovery-note.txt", _format_template("Recovered marker: {flag}\n", mapping))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate service node variant artifacts")
    parser.add_argument("--input", type=Path, default=Path("/inputs"))
    parser.add_argument("--output", type=Path, default=Path("/outputs"))
    parser.add_argument("--variant", default=os.environ.get("SERVICE_VARIANT_ID", "ftp_anonymous_finance_drop"))
    args = parser.parse_args()

    variant_id = str(args.variant or "").strip()
    variant = VARIANTS.get(variant_id)
    if not variant:
        raise SystemExit(f"[validation error] unknown service variant: {variant_id}")

    cfg = _read_json(args.input / "config.json")
    try:
        seed = str(cfg.get("seed") or "").strip()
        node_name = str(cfg.get("node_name") or "").strip()
        if not seed or not node_name:
            raise ValueError("seed and node_name are required")
        port = _int_range(cfg.get("service_port"), int(variant.get("default_port") or 9000), name="service_port", minimum=1, maximum=65535)
        parsed_credential = _parse_credential(cfg.get("Credential(user, password)"))
    except ValueError as exc:
        raise SystemExit(f"[validation error] {exc}") from exc

    digest = _digest(seed, node_name, variant_id, length=10)
    needs_credential = str(variant.get("auth") or "none") == "password"
    if parsed_credential:
        username, password = parsed_credential
    elif needs_credential:
        username = f"{variant.get('user_prefix') or variant.get('service')}_{digest[:6]}"
        password = f"Svc-{digest[6:]}!"
    else:
        username = str(variant.get("auth") or "anonymous")
        password = ""

    token = _digest(seed, variant_id, "token", length=24)
    api_key = "ak_" + _digest(seed, variant_id, "api", length=28)
    flag_value = _flag(seed, node_name, variant_id, str(cfg.get("flag_prefix") or "FLAG"))
    mapping = {
        "api_key": api_key,
        "digest": digest,
        "flag": flag_value,
        "node": node_name,
        "password": password,
        "port": port,
        "token": token,
        "user": username,
    }

    service_root = args.output / "service"
    for raw_rel, raw_body in (variant.get("files") or {}).items():
        rel = _format_template(raw_rel, mapping).lstrip("/")
        body = _format_template(raw_body, mapping)
        _write_text(service_root / rel, body)

    flag_path = _format_template(str(variant.get("flag_path") or "flag.txt"), mapping).lstrip("/")
    if not (service_root / flag_path).exists():
        _write_text(service_root / flag_path, flag_value + "\n")

    archive_rel = str(variant.get("archive_path") or "").strip().lstrip("/")
    if archive_rel:
        _write_archive(service_root, archive_rel, mapping)

    endpoint = _format_template(str(variant.get("endpoint") or "/" + flag_path), mapping)
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    service_name = str(variant.get("service") or variant.get("pack") or "service")
    protocol = str(variant.get("protocol") or service_name)
    banner = f"{service_name.upper()} lab service {digest} ({variant.get('title') or variant_id})"
    service_config = {
        "variant_id": variant_id,
        "service": service_name,
        "protocol": protocol,
        "title": str(variant.get("title") or variant_id),
        "auth": str(variant.get("auth") or "none"),
        "username": username,
        "password": password,
        "endpoint": endpoint,
        "flag_path": flag_path,
        "port": port,
        "banner": banner,
        "help": "Use LIST to enumerate files and GET <path> to read one. Service-specific aliases are also supported.\n",
    }
    _write_text(service_root / "config.json", json.dumps(service_config, indent=2) + "\n")
    _write_text(args.output / "service.py", _service_script(), mode=0o755)
    _write_text(args.output / "Dockerfile", _challenge_dockerfile(port))
    _write_text(args.output / "docker-compose.yml", _compose(port, f"{service_name}-{digest[:6]}"))

    outputs: dict[str, Any] = {
        "Flag(flag_id)": flag_value,
        "FlagDelivery(mode)": "file",
        "FlagFile(path)": flag_path,
        "File(path)": "docker-compose.yml",
        "Directory(host, path)": "service",
        "PortForward(host, port)": port,
        "Endpoint(path)": endpoint,
        "Version(service)": f"{service_name}-simulated-{protocol}",
    }
    if needs_credential or parsed_credential:
        outputs["Credential(user, password)"] = f"{username}:{password}"
    for fact, raw_value in (variant.get("extra_facts") or {}).items():
        outputs[str(fact)] = _format_template(raw_value, mapping)

    _write_text(
        args.output / "outputs.json",
        json.dumps({"generator_id": str(cfg.get("generator_id") or variant_id), "outputs": outputs}, indent=2) + "\n",
    )


if __name__ == "__main__":
    main()