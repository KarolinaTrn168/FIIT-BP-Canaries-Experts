import re
import sql_database
from sql_database import Mail_Passwd_IP
import search_canaries

# Expert Dovecot
class DovecotExpert:
    #nastavim, ktore programy expert akceptuje
    accepted_programs = ['dovecot']

    callback = None      #funkcia sa bude volat na odoslanie spatnej spravy do LogParser.py

    logy = []
    
    #initializacia experta (zkompilovanie regexov)
    def __init__(self, c):
        self.callback = c       #nastavenie callback na pointer, aby sa dala volat funkcia v LogParser.py
        self.IMAP = re.compile(r"""imap""")
        self.LMTP = re.compile(r"""lmtp""")

    

    #prijatie logu
    def receive(self, log, r):
        self.Mail = re.compile(r'(?:\.?)([\w\-_+#~!$&\'\.]+(?<!\.)(@|[ ]?\(?[ ]?(at|AT)[ ]?\)?[ ]?)(?<!\.)[\w]+[\w\-\.]*\.[a-zA-Z-]{2,3})(?:[^\w])')
        matchMail = self.Mail.search(log['message'])

        self.IP = re.search(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))', log['message'])

        self.Password = re.search(r'given password: (.*)\)', log['message'])

        self.SHA = re.compile(r"""SHA512-CRYPT""")

        self.PID = re.compile(r'(?:pid=)([1,2,3,4,5,6,7,8,9,0]*)')
        matchPID = self.PID.search(log['message'])

        if self.IMAP.search(log['message']):        #spracuje SMTP
            return
        
        if self.LMTP.search(log['message']):        #spracuje SMTP
            return

        if matchMail:
            self.callback({'expert': 'Dovecot Expert',
                            'mail': matchMail.group(1),
                            'password': self.Password.group(1) if self.Password else None,
                            'IP': self.IP.group(1) if self.IP else None,
                            'time': log['time']})
            if self.Password:
                sql_database.mail_information(matchMail.group(1), self.Password.group(1), self.IP.group(1) if self.IP else None, log['time'])

           # search_canaries.search_canary(matchMail.group(1))
                #if sql_database.mail_information(matchMail.group(1), self.Password.group(1), self.IP.group(1) if self.IP else None, log['time']) == 0:
                    #print('tak teda bol...')
                #    search_canaries.search_canary(matchMail.group(1))

                
            #if sql_database.Mail_Passwd_IP.select().where(sql_database.Mail_Passwd_IP.mail == matchMail.group(1)):
            #    if self.SHA.search(log['message']):
            #        print('je tu SHA') 
            #        self.SHA_passwd = re.search(r"!= '(.*)'", log['message'])
            #        if self.SHA_passwd:
            #            print('zakodovane je: ', self.SHA_passwd.group(1))
            return

        if matchPID:
            self.callback({'expert': 'Dovecot Expert',
                            'sprava': 'Client connected.',
                            'PID': matchPID.group(1)})
            return

        return 