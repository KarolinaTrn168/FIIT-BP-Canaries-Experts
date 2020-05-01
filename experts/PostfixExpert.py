import re
import logging

logging.basicConfig(filename='analyzed.log', level=logging.WARNING, 
                    format='%(message)s')

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
            r.rpush('mail_list', json.dumps({'time':log['time'], 'message':log['message'], 'program':log['program']}))
            try:
                try:
                    logging.warning({'mail': matchMail.group(1),
                                'password': 'true',
                                'IP': self.IP.group(1) if self.IP else None,
                                'status': 'SUCCESS', 
                                'domain': search_canaries.search_canary(matchMail.group(1))[1][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
                                'site': search_canaries.search_canary(matchMail.group(1))[0][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
                                'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'] })
                except:
                    logging.warning({'mail': matchMail.group(1),
                                'password': 'true',
                                'IP': self.IP.group(1) if self.IP else None,
                                'status': 'SUCCESS',
                                'domain': search_canaries.search_canary(matchMail.group(1))[1]['details'],
                                'site': search_canaries.search_canary(matchMail.group(1))[0]['details'],
                                'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'] })
            except:
                logging.warning({'mail': matchMail.group(1),
                            'password': 'true',
                            'IP': self.IP.group(1) if self.IP else None,
                            'status': 'SUCCESS', 
                            'details': 'NOT a canary' })
            return

#        elif self.noqueue and self.proto and self.from_mail and self.to_mail and self.relay_denied:       #SMTP-Honeypot is used -- Relay access denied
#           json.dump(log, file)
#           file.write('\n') 
#           r.rpush('mail_list', json.dumps({'time':log['time'], 'message':log['message'], 'program':log['program']}))
#           try:
#                try:
#                    logging.warning({'mail_from': self.from_mail.group(1),
#                                'mail_to': self.to_mail.group(1),
#                                'IP': self.IP.group(1) if self.IP else None,
#                                'status': 'FAIL', 
#                                'domain': search_canaries.search_canary(matchMail.group(1))[1][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
#                                'site': search_canaries.search_canary(matchMail.group(1))[0][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
#                                'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'],
#                                'message': 'Relay access denied' })
#                except:
#                    logging.warning({'mail_from': self.from_mail.group(1),
#                                'mail_to': self.to_mail.group(1),
#                                'IP': self.IP.group(1) if self.IP else None,
#                                'status': 'FAIL',
#                                'domain': search_canaries.search_canary(matchMail.group(1))[1]['details'],
#                                'site': search_canaries.search_canary(matchMail.group(1))[0]['details'],
#                                'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'],
#                                'message': 'Relay access denied' })
#            except:
#                logging.warning({'mail_from': self.from_mail.group(1),
#                            'mail_to': self.to_mail.group(1),
#                            'IP': self.IP.group(1) if self.IP else None,
#                            'status': 'FAIL', 
#                            'message': 'Relay access denied' })
#            return

#        elif self.noqueue and self.proto and self.from_mail and self.to_mail and self.host_rejected:       #SMTP-Honeypot is used -- Host is rejected
#           json.dump(log, file)
#            file.write('\n') 
#           r.rpush('mail_list', json.dumps({'time':log['time'], 'message':log['message'], 'program':log['program']}))
#           try:
#                try:
#                    logging.warning({'mail_from': self.from_mail.group(1),
#                                'mail_to': self.to_mail.group(1),
#                                'IP': self.IP.group(1) if self.IP else None,
#                                'status': 'FAIL', 
#                                'domain': search_canaries.search_canary(matchMail.group(1))[1][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
#                                'site': search_canaries.search_canary(matchMail.group(1))[0][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
#                                'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'],
#                                'message': 'Client host rejected - cannot find reverse hostname' })
#                except:
#                    logging.warning({'mail_from': self.from_mail.group(1),
#                                'mail_to': self.to_mail.group(1),
#                                'IP': self.IP.group(1) if self.IP else None,
#                                'status': 'FAIL',
#                                'domain': search_canaries.search_canary(matchMail.group(1))[1]['details'],
#                                'site': search_canaries.search_canary(matchMail.group(1))[0]['details'],
#                                'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'],
#                                'message': 'Client host rejected - cannot find reverse hostname' })
#            except:
#                logging.warning({'mail_from': self.from_mail.group(1),
#                            'mail_to': self.to_mail.group(1),
#                            'IP': self.IP.group(1) if self.IP else None,
#                            'status': 'FAIL', 
#                            'message': 'Client host rejected - cannot find reverse hostname' })
#            return

        else: 
            return
