import re

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


        if self.unknown_connection:
            return
        elif self.method and self.username and matchMail:
            self.callback({'expert': 'SMTP Expert',
                           'IP': self.IP.group(1),
                           'message': 'SUCCESSFUL connection to: ' + matchMail.group(1) })
            return

        elif self.noqueue and self.proto and self.from_mail and self.to_mail:
            self.callback({'expert': 'SMTP Expert',
                           'message': 'Relay access denied from: ' + self.from_mail.group(1) + ' to: ' + self.to_mail.group(1) + '.'})

        else: 
            return