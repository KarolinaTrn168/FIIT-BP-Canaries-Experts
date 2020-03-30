import re

# Expert Postfix
class PostfixExpert:
    accepted_programs = ['postfix/smtpd']

    callback = None

    re1 = None

    #initializacia experta
    def __init__(self, c):
        self.callback = c
        self.re1 = re.compile(r"""disconnect from unknown""")
        self.re2 = re.compile(r"""connect from unknown""")

    #prijatie logu
    def receive(self, log):
        if self.re1.search(log['message']):
            self.callback({'expert': 'Postfix Expert',
                           'status': 'Disconnect from unknown.' })
                           #'sprava': log['message']})
            return
        
        elif self.re2.search(log['message']):
            self.callback({'expert': 'Postfix Expert',
                           'status': 'Connect from unknown.' })
                           #'sprava': log['message']})
            return

        self.callback({'expert': 'Postfix Expert',
                       'status': 'Ziadna zhoda!',
                       'sprava': log['message']})