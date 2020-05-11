import re
import logging
import logging.handlers
import json


with open('config.json', encoding='utf8') as config_file:
      Config = json.load(config_file)


logger = logging.getLogger('canary-experts')
logger.setLevel(logging.INFO)

syslog = logging.handlers.SysLogHandler(address='/dev/log')
syslog.setFormatter(logging.Formatter(
    '%(name)s: [%(levelname)s] %(message)s'
))
logger.addHandler(syslog)

remote_syslog = logging.handlers.SysLogHandler(address=(Config['logger']['IP'], Config['logger']['port']), facility=logging.handlers.SysLogHandler.LOG_SYSLOG)
remote_syslog.setFormatter(logging.Formatter(
    '%(name)s: [%(levelname)s] %(message)s'
))
logger.addHandler(remote_syslog)


file = open('analyzed_logs.txt', 'a')

# Expert Postfix
class PostfixExpert:
    accepted_programs = ['postfix/smtpd', 'postfix/anvil', 'postfix/smtps/smtpd', 'postfix/submission/smtpd', 'postfix/cleanup', 'postfix/qmgr', 'postfix/lmtp', 'postfix/scache', 'postfix/bounce', 'postfix/error', 'postfix/postfix-script', 'postfix/master']

    callback = None

    re1 = None

    #initializacia experta
    def __init__(self, c):
        self.callback = c

    #prijatie logu
    def receive(self, log, r):
        self.unknown_connection = re.search(r"disconnect from unknown|connect from unknown|lost connection after AUTH from unknown", log['message'])
        
        self.method = re.search(r'sasl_method=PLAIN', log['message'])
        self.username = re.search(r'sasl_username=', log['message'])

        self.Mail = re.compile(r'(?:\.?)([\w\-_+#~!$&\'\.]+(?<!\.)(@|[ ]?\(?[ ]?(at|AT)[ ]?\)?[ ]?)(?<!\.)[\w]+[\w\-\.]*\.[a-zA-Z-]{2,3})(?:[^\w])')
        matchMail = self.Mail.search(log['message'])

        self.IP = re.search(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))', log['message'])

        self.noqueue = re.search(r'NOQUEUE: reject: RCPT from', log['message'])

        self.from_mail = re.search(r'from=<([\w\-_+#~!$&\'\.]+(?<!\.)(@|[ ]?\(?[ ]?(at|AT)[ ]?\)?[ ]?)(?<!\.)[\w]+[\w\-\.]*\.[a-zA-Z-]{2,3})>', log['message'])

        self.to_mail = re.search(r'to=<([\w\-_+#~!$&\'\.]+(?<!\.)(@|[ ]?\(?[ ]?(at|AT)[ ]?\)?[ ]?)(?<!\.)[\w]+[\w\-\.]*\.[a-zA-Z-]{2,3})>', log['message'])

        self.proto = re.search(r'proto=ESMTP', log['message'])

        self.host_rejected = re.search(r'Client host rejected:', log['message'])
        self.relay_denied = re.search(r'Relay access denied', log['message'])


        if self.unknown_connection:
            return
        elif self.method and self.username and matchMail:       #SMTP, Successful connection
            json.dump(log, file)
            file.write('\n')
            r.rpush('analyzed_logs', json.dumps({'time':log['time'], 'message':log['message'], 'program':log['program']}))
            try:
                try:
                    logger.warning({'expert': 'SMTP Expert',
                                'mail': matchMail.group(1),
                                'password': 'true',
                                'IP': self.IP.group(1) if self.IP else None,
                                'status': 'SUCCESS', 
                                'domain': search_canaries.search_canary(matchMail.group(1))[1][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
                                'site': search_canaries.search_canary(matchMail.group(1))[0][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
                                'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'] })
                except:
                    try:
                        logger.warning({'expert': 'SMTP Expert',
                                    'mail': matchMail.group(1),
                                    'password': 'true',
                                    'IP': self.IP.group(1) if self.IP else None,
                                    'status': 'SUCCESS', 
                                    'domain': search_canaries.search_canary(matchMail.group(1))[1]['details'],
                                    'site': search_canaries.search_canary(matchMail.group(1))[0][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
                                    'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'] })
                    except:
                        try:
                            logger.warning({'expert': 'SMTP Expert',
                                        'mail': matchMail.group(1),
                                        'password': 'true',
                                        'IP': self.IP.group(1) if self.IP else None,
                                        'status': 'SUCCESS', 
                                        'domain': search_canaries.search_canary(matchMail.group(1))[1][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
                                        'site': search_canaries.search_canary(matchMail.group(1))[0]['details'],
                                        'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'] })
                        except:
                            logger.warning({'expert': 'SMTP Expert',
                                        'mail': matchMail.group(1),
                                        'password': 'true',
                                        'IP': self.IP.group(1) if self.IP else None,
                                        'status': 'SUCCESS',
                                        'domain': search_canaries.search_canary(matchMail.group(1))[1]['details'],
                                        'site': search_canaries.search_canary(matchMail.group(1))[0]['details'],
                                        'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'] })
            except:
                logger.warning({'expert': 'SMTP Expert',
                            'mail': matchMail.group(1),
                            'password': 'true',
                            'IP': self.IP.group(1) if self.IP else None,
                            'status': 'SUCCESS', 
                            'details': 'NOT a canary' })
            return


        elif self.noqueue and self.proto and self.from_mail and self.to_mail and self.relay_denied:       #SPAM-Honeypot is used -- Relay access denied
            json.dump(log, file)
            file.write('\n') 
            r.rpush('analyzed_logs', json.dumps({'time':log['time'], 'message':log['message'], 'program':log['program']}))
            try:
                try:
                    logging.warning({'expert': 'SPAM Expert',
                                    'mail_from': self.from_mail.group(1),
                                     'mail_to': self.to_mail.group(1),
                                     'IP': self.IP.group(1) if self.IP else None,
                                     'status': 'FAIL', 
                                     'domain': search_canaries.search_canary(self.from_mail.group(1))[1][search_canaries.search_canary(self.from_mail.group(1))[2]['uuid']],
                                     'site': search_canaries.search_canary(self.from_mail.group(1))[0][search_canaries.search_canary(self.from_mail.group(1))[2]['uuid']],
                                     'testing': search_canaries.search_canary(self.from_mail.group(1))[2]['testing'],
                                     'message': 'SPAM through ' + self.from_mail.group(1) })
                except:
                    try:
                        logging.warning({'expert': 'SPAM Expert',
                                        'mail_from': self.from_mail.group(1),
                                        'mail_to': self.to_mail.group(1),
                                        'IP': self.IP.group(1) if self.IP else None,
                                        'status': 'FAIL', 
                                        'domain': search_canaries.search_canary(self.from_mail.group(1))[1]['details'],
                                        'site': search_canaries.search_canary(self.from_mail.group(1))[0][search_canaries.search_canary(self.from_mail.group(1))[2]['uuid']],
                                        'testing': search_canaries.search_canary(self.from_mail.group(1))[2]['testing'],
                                        'message': 'SPAM through ' + self.from_mail.group(1) })
                    except:
                        try:
                            logging.warning({'expert': 'SPAM Expert',
                                            'mail_from': self.from_mail.group(1),
                                            'mail_to': self.to_mail.group(1),
                                            'IP': self.IP.group(1) if self.IP else None,
                                            'status': 'FAIL', 
                                            'domain': search_canaries.search_canary(self.from_mail.group(1))[1][search_canaries.search_canary(self.from_mail.group(1))[2]['uuid']],
                                            'site': search_canaries.search_canary(self.from_mail.group(1))[0]['details'],
                                            'testing': search_canaries.search_canary(self.from_mail.group(1))[2]['testing'],
                                            'message': 'SPAM through ' + self.from_mail.group(1) })
                        except:
                            try:
                                logging.warning({'expert': 'SPAM Expert',
                                                'mail_from': self.from_mail.group(1),
                                                'mail_to': self.to_mail.group(1),
                                                'IP': self.IP.group(1) if self.IP else None,
                                                'status': 'FAIL',
                                                'domain': search_canaries.search_canary(self.from_mail.group(1))[1]['details'],
                                                'site': search_canaries.search_canary(self.from_mail.group(1))[0]['details'],
                                                'testing': search_canaries.search_canary(self.from_mail.group(1))[2]['testing'],
                                                'message': 'SPAM through ' + self.from_mail.group(1) })
                            except:
                                try:
                                    logging.warning({'expert': 'SPAM Expert',
                                                'mail_from': self.from_mail.group(1),
                                                'mail_to': self.to_mail.group(1),
                                                'IP': self.IP.group(1) if self.IP else None,
                                                'status': 'FAIL', 
                                                'domain': search_canaries.search_canary(self.to_mail.group(1))[1][search_canaries.search_canary(self.to_mail.group(1))[2]['uuid']],
                                                'site': search_canaries.search_canary(self.to_mail.group(1))[0][search_canaries.search_canary(self.to_mail.group(1))[2]['uuid']],
                                                'testing': search_canaries.search_canary(self.to_mail.group(1))[2]['testing'],
                                                'message': 'SPAM through ' + self.to_mail.group(1) })
                                except:
                                    try:
                                        logging.warning({'expert': 'SPAM Expert',
                                                    'mail_from': self.from_mail.group(1),
                                                    'mail_to': self.to_mail.group(1),
                                                    'IP': self.IP.group(1) if self.IP else None,
                                                    'status': 'FAIL', 
                                                    'domain': search_canaries.search_canary(self.to_mail.group(1))[1]['details'],
                                                    'site': search_canaries.search_canary(self.to_mail.group(1))[0][search_canaries.search_canary(self.to_mail.group(1))[2]['uuid']],
                                                    'testing': search_canaries.search_canary(self.to_mail.group(1))[2]['testing'],
                                                    'message': 'SPAM through ' + self.to_mail.group(1) })
                                    except:
                                        try:
                                            logging.warning({'expert': 'SPAM Expert',
                                                        'mail_from': self.from_mail.group(1),
                                                        'mail_to': self.to_mail.group(1),
                                                        'IP': self.IP.group(1) if self.IP else None,
                                                        'status': 'FAIL', 
                                                        'domain': search_canaries.search_canary(self.to_mail.group(1))[1][search_canaries.search_canary(self.to_mail.group(1))[2]['uuid']],
                                                        'site': search_canaries.search_canary(self.to_mail.group(1))[0]['details'],
                                                        'testing': search_canaries.search_canary(self.to_mail.group(1))[2]['testing'],
                                                        'message': 'SPAM through ' + self.to_mail.group(1) })
                                        except:
                                            logging.warning({'expert': 'SPAM Expert',
                                                            'mail_from': self.from_mail.group(1),
                                                            'mail_to': self.to_mail.group(1),
                                                            'IP': self.IP.group(1) if self.IP else None,
                                                            'status': 'FAIL',
                                                            'domain': search_canaries.search_canary(self.to_mail.group(1))[1]['details'],
                                                            'site': search_canaries.search_canary(self.to_mail.group(1))[0]['details'],
                                                            'testing': search_canaries.search_canary(self.to_mail.group(1))[2]['testing'],
                                                            'message': 'SPAM through ' + self.to_mail.group(1) })
            except:
                return
        
            return

        else: 
            return
