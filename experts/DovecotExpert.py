import re
import json
import sql_database
from sql_database import SMTP
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


    #prijatie logu
    def receive(self, log, r):        
        self.Mail = re.compile(r'(?:\.?)([\w\-_+#~!$&\'\.]+(?<!\.)(@|[ ]?\(?[ ]?(at|AT)[ ]?\)?[ ]?)(?<!\.)[\w]+[\w\-\.]*\.[a-zA-Z-]{2,3})(?:[^\w])')
        matchMail = self.Mail.search(log['message'])

        self.IP = re.search(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))', log['message'])

        self.Password = re.search(r'given password: (.*)\)', log['message'])

        self.Mismatch_passwd = re.search(r'Password mismatch', log['message'])

        self.PID = re.compile(r'(?:pid=)([1,2,3,4,5,6,7,8,9,0]*)')
        matchPID = self.PID.search(log['message'])

        self.msgid = re.search(r'msgid=<(.*)>:', log['message'])

        self.saved_inbox = re.search(r'saved mail to INBOX', log['message'])

        self.plain = re.search(r"PLAIN", log['message'])
        
        self.service_smtp = re.search(r"service=smtp", log['message'])
        
        self.service_imap = re.search(r"service=imap", log['message'])

        self.secured = re.search(r"secured", log['message'])
        
        self.nologin = re.search(r"nologin", log['message'])
       
        self.base64 = re.search(r"base64 data may contain sensitive data", log['message'])
       
        self.lip = re.compile(r'(?:lip=)((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))')
        matchlip = self.lip.search(log['message'])
       
        self.rip = re.compile(r'(?:rip=)((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))')
        matchrip = self.rip.search(log['message'])
       
        self.lport = re.compile(r'(?:lport=)([1,2,3,4,5,6,7,8,9,0]*)')
        matchlport = self.lport.search(log['message'])

        self.rport = re.compile(r'(?:rport=)([1,2,3,4,5,6,7,8,9,0]*)')
        matchrport = self.rport.search(log['message'])

        self.imap_login = re.search(r'imap-login', log['message'])

        self.mpid = re.search(r'mpid', log['message'])

        self.OK = re.search(r'client passdb out: OK', log['message'])
        self.FAIL = re.search(r'client passdb out: FAIL', log['message'])
        self.CONT = re.search(r'client passdb out: CONT', log['message'])

        self.SHA512 = re.search(r'SHA512-CRYPT', log['message'])
        self.unequal = re.search(r'!=', log['message'])
        self.used_password = re.search(r'SHA512-CRYPT\((.*)\)', log['message'])



        if matchMail:
            if self.Mismatch_passwd:
                self.callback({'expert': 'SMTP Expert',
                                    'mail': matchMail.group(1),
                                    'password': self.Password.group(1) if self.Password else None,
                                    'IP': self.IP.group(1) if self.IP else None,
                                    'message': 'Attempt to FAILED with wrong password!'})
                return

            elif self.saved_inbox:
                self.callback({'expert': 'SMTP Expert',
                                'mail': matchMail.group(1),
                                'message': 'Deliverd mail via dovecot (Saved to Inbox).'})
                return
            
            elif self.OK:
                self.callback({'status': 'OK',
                            'message': 'The authentication to ' + matchMail.group(1) + ' SUCCEED.'})
                return
            
            elif self.FAIL:
                self.callback({'status': 'FAIL',
                            'message': 'The authentication to ' + matchMail.group(1) + ' FAILED.'})
                return

            elif self.SHA512 and self.unequal:
                self.callback({'expert': 'IMAP Expert',
                            'mail': matchMail.group(1),
                            'password': self.used_password.group(1) if self.used_password else None,
                            'IP': self.IP.group(1) if self.IP else None,
                            'message': 'Attempt to FAILED with wrong password!'})
                return

            elif self.imap_login and self.plain and self.mpid:
                self.callback({'expert': 'IMAP Expert', 
                            'mail': matchMail.group(1),
                            'message': 'SUCCESSFUL connection from ' + matchlip.group(1) + ' to ' + matchrip.grouo(1) + '.'})
                return


        elif self.plain and self.service_smtp and self.nologin and self.secured:
            self.callback({'expert': 'SMTP Expert',
                                'message': 'Attempt to connect from ' + matchlip.group(1) + ' to ' + matchrip.group(1) + ' FAILED!'})
            return

        elif self.plain and self.service_imap and self.secured and self.base64:
            self.callback({'expert': 'IMAP Expert',
                           'message': 'SUCCESSFUL connection from ' + matchlip.group(1) + ' to ' + matchrip.group(1) + 'ports: src: ' + matchlport.group(1) + ' dst: ' + matchrport.group(1) + '.'})
            return

        elif self.CONT:
            self.callback({'status': 'CONT',
                           'message': 'The authentication continues, and more data is expected from client to finish the authentication.'})
            return

        else:
            return 