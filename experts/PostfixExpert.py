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
    def receive(self, log, r):
        self.unknown_connection = re.search(r"disconnect from unknown|connect from unknown|lost connection after AUTH from unknown", log['message'])
        if self.unknown_connection:
           # self.callback({'expert': 'Postfix Expert',
           #                'status': 'Disconnect or connect or lost connection from unknown.' })
                        #'sprava': log['message']})
            return

        self.callback({'expert': 'Postfix Expert',
                       'status': 'Ziadna zhoda!',
                       'sprava': log['message']})