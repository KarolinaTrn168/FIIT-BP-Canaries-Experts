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
        if self.re1.search(log['message']):
            if self.re2.search(log['message']):
                self.callback({'expert': 'SMTP Expert',
                               'status': 'Local Mail Transfer Protocol (LMTP) used.' })
                               #'sprava': log['message']})
            else:
                self.callback({'expert': 'SMTP Expert',
                               'status': 'Something with LMTP used...',
                               'sprava': log['message']})
            return  