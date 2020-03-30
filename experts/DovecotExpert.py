import re

# Expert Dovecot
class DovecotExpert:
    #nastavim, ktore programy expert akceptuje
    accepted_programs = ['dovecot']

    callback = None      #funkcia sa bude volat na odoslanie spatnej spravy do LogParser.py
    #skusobny regex
    re1 = None
    re2 = None
    #initializacia experta (zkompilovanie regexov)
    def __init__(self, c):
        self.callback = c       #nastavenie callback na pointer, aby sa dala volat funkcia v LogParser.py
        self.re1 = re.compile(r"""Password mismatch""")
        self.re2 = re.compile(r"""imap""")

    #prijatie logu
    def receive(self, log):
        if self.re2.search(log['message']):
            return

        if self.re1.search(log['message']):
            self.callback({'expert': 'Dovecot Expert',
                           'status': 'Nasiel som zhodu!',
                           'sprava': log['message']})
            return

        self.callback({'expert': 'Dovecot Expert',
                       'status': 'Ziadna zhoda!',
                       'sprava': log['message']})