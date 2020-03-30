import re

# Expert IMAP
class IMAPExpert:
    accepted_programs = ['dovecot']

    callback = None

    re1 = None
    re2 = None 
    #initializacia experta
    def __init__(self, c):
        self.callback = c
        self.re1 = re.compile(r"""imap""")
        self.re2 = re.compile(r"""Disconnected""")

    #prijatie logu
    def receive(self, log):
        if self.re1.search(log['message']):
            if self.re2.search(log['message']):
                self.callback({'expert': 'IMAP Expert',
                               'status': 'Disconnected after no auth attempts!' })
                               #'sprava': log['message']})
            else:
                self.callback({'expert': 'IMAP Expert',
                               'status': 'Something happened...',
                               'sprava': log['message']})
            return