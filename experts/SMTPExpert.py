import re

# Expert SMTP
class SMTPExpert:
    accepted_programs = ['dovecot']

    callback = None

    re1 = None 
    re2 = None 
    #initializacia experta
    def __init__(self, c):
        self.callback = c
        self.re1 = re.compile(r"""lmtp""")
        self.re2 = re.compile(r"""Connect from local""")

    #prijatie logu
    def receive(self, log, r):
        self.Mail = re.compile(r'(?:\.?)([\w\-_+#~!$&\'\.]+(?<!\.)(@|[ ]?\(?[ ]?(at|AT)[ ]?\)?[ ]?)(?<!\.)[\w]+[\w\-\.]*\.[a-zA-Z-]{2,3})(?:[^\w])')
        matchMail = self.Mail.search(log['message'])

        self.msgid = re.search(r'msgid=<(.*)>:', log['message'])

        self.saved_inbox = re.search(r'saved mail to INBOX', log['message'])

        if matchMail:
            self.callback({'expert': 'SMTP Expert',
                            'mail': matchMail.group(1),
                            'sprava': 'Saved mail.' if self.saved_inbox else 'nieco ine'})
        return

        if self.re1.search(log['message']) or self.re2.search(log['message']):
            return  