import re
import json
import search_canaries
import base64
import logging
import logging.handlers
#from logging.handlers.SysLogHandler import LOG_SYSLOG


with open('config.json', encoding='utf8') as config_file:
      Config = json.load(config_file)

# logger.basicConfig(filename='analyzed.log', level=logging.WARNING, 
#                     format='%(message)s')

logger = logging.getLogger('canary-experts')
logger.setLevel(logging.INFO)
# handler = logging.handlers.SysLogHandler(address=(Config['logger']['IP'], Config['logger']['port']), facility=logging.handlers.SysLogHandler.LOG_SYSLOG)
# handler.setFormatter(logging.Formatter('%(message)s'))
# logger.addHandler(handler)
syslog = logging.handlers.SysLogHandler(address='/dev/log')
syslog.setFormatter(logging.Formatter(
    '%(name)s: [%(levelname)s] %(message)s'
))
logger.addHandler(syslog)

remote_syslog = logging.handlers.SysLogHandler(address=('localhost', 12345), facility=logging.handlers.SysLogHandler.LOG_SYSLOG)
remote_syslog.setFormatter(logging.Formatter(
    '%(name)s: [%(levelname)s] %(message)s'
))
logger.addHandler(remote_syslog)



#logger.addHandler(syslog)



file = open('analyzed_logs.txt', 'a')



# Expert Dovecot
class DovecotExpert:
    #nastavim, ktore programy expert akceptuje
    accepted_programs = ['dovecot']

    callback = None      #funkcia sa bude volat na odoslanie spatnej spravy do LogParser.py

    #initializacia experta (zkompilovanie regexov)
    def __init__(self, c):
        self.callback = c       #nastavenie callback na pointer, aby sa dala volat funkcia v LogParser.py    


    #prijatie logu
    def receive(self, log, r):    
        logger.info('Checking log message.')
        #print(search_canaries.search_canary('benesrene@cloudmail.ga')[2]) 

        self.Mail = re.compile(r'(?:\.?)([\w\-_+#~!$&\'\.]+(?<!\.)(@|[ ]?\(?[ ]?(at|AT)[ ]?\)?[ ]?)(?<!\.)[\w]+[\w\-\.]*\.[a-zA-Z-]{2,3})(?:[^\w])')
        matchMail = self.Mail.search(log['message'])

        self.IP = re.search(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))', log['message'])

        self.Password = re.search(r'given password: (.*)\)', log['message'])

        self.Mismatch_passwd = re.search(r'Password mismatch', log['message'])

        self.plain = re.search(r"PLAIN", log['message'])
                
        self.service_imap = re.search(r"service=imap", log['message'])

        self.secured = re.search(r"secured", log['message'])
               
        self.base64 = re.search(r"base64 data may contain sensitive data", log['message'])

        self.response = re.compile(r'(?:resp=)(.*) \(previous')
        matchResponse = self.response.search(log['message'])
       
        self.lip = re.compile(r'(?:lip=)((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))')
        matchlip = self.lip.search(log['message'])

        self.SHA512 = re.search(r'SHA512-CRYPT', log['message'])
        self.unequal = re.search(r'!=', log['message'])
        self.used_password = re.search(r'SHA512-CRYPT\((.*)\)', log['message'])

        #print(search_canaries.search_canary('benesrene@cloudmail.ga')[2]['testing'])

        if matchMail:
            json.dump(log, file)
            file.write('\n')
            r.rpush('mail_list', json.dumps({'time':log['time'], 'message':log['message'], 'program':log['program']}))
            if self.Mismatch_passwd:        #SMTP, attempt to connect failed with wrong password
                try:
                    uuid = search_canaries.search_canary(matchMail.group(1))[2]['uuid']
                    print(uuid)
                    try:
                        logger.warning({'mail': matchMail.group(1),
                                    'password': self.Password.group(1) if self.Password else None,
                                    'IP': self.IP.group(1) if self.IP else None,
                                    'status': 'FAIL', 
                                    'domain': search_canaries.search_canary(matchMail.group(1))[1][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
                                    'site': search_canaries.search_canary(matchMail.group(1))[0][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
                                    'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'] })
                    except:
                        logger.warning({'mail': matchMail.group(1),
                                    'password': self.Password.group(1) if self.Password else None,
                                    'IP': self.IP.group(1) if self.IP else None,
                                    'status': 'FAIL',
                                    'domain': search_canaries.search_canary(matchMail.group(1))[1]['details'],
                                    'site': search_canaries.search_canary(matchMail.group(1))[0]['details'],
                                    'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'] })
                except:
                    logger.warning({'mail': matchMail.group(1),
                                'password': self.Password.group(1) if self.Password else None,
                                'IP': self.IP.group(1) if self.IP else None,
                                'status': 'FAIL', 
                                'details': 'NOT a canary' })
                return

            elif self.SHA512 and self.unequal:      #IMAP, attempt to connect failed with wrong password
                try:
                    try:
                        logger.warning({'mail': matchMail.group(1),
                                    'password': self.used_password.group(1) if self.used_password else None,
                                    'IP': self.IP.group(1) if self.IP else None,
                                    'status': 'FAIL', 
                                    'domain': search_canaries.search_canary(matchMail.group(1))[1][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
                                    'site': search_canaries.search_canary(matchMail.group(1))[0][search_canaries.search_canary(matchMail.group(1))[2]['uuid']],
                                    'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'] })
                    except:
                        logger.warning({'mail': matchMail.group(1),
                                    'password': self.used_password.group(1) if self.used_password else None,
                                    'IP': self.IP.group(1) if self.IP else None,
                                    'status': 'FAIL',
                                    'domain': search_canaries.search_canary(matchMail.group(1))[1]['details'],
                                    'site': search_canaries.search_canary(matchMail.group(1))[0]['details'],
                                    'testing': search_canaries.search_canary(matchMail.group(1))[2]['testing'] })
                except:
                    logger.warning({'mail': matchMail.group(1),
                                'password': self.used_password.group(1) if self.used_password else None,
                                'IP': self.IP.group(1) if self.IP else None,
                                'status': 'FAIL', 
                                'details': 'NOT a canary' })
                    #formatter = logging.Formatter('Python: {"mail":"%(matchMail.group(1))s", "password":"%(slef.used_password.group(1))s", "IP":"%(selft.IP.group(1))s", "status":"FAIL", "detail":"NOT a canary"}')
                return

        elif self.plain and self.service_imap and self.secured and self.base64:     #IMAP, Successful connection
            json.dump(log, file)
            file.write('\n')
            r.rpush('mail_list', json.dumps({'time':log['time'], 'message':log['message'], 'program':log['program']}))

            base64_message = matchResponse.group(1)
            base64_message += "=" * ((4 - len(base64_message) % 4) % 4)
            base64_bytes = base64_message.encode('ascii')
            message_bytes = base64.b64decode(base64_bytes)
            final_response = message_bytes.decode('ascii')

            matchMail2 = self.Mail.search(final_response)

            Mail = matchMail2.group(1)
            self.Pass = re.compile(r'(?:' +Mail+ ')(.*)')
            matchPass = self.Pass.search(final_response)
            try:
                try:
                    logger.warning({'mail': matchMail2.group(1),
                                #'password': matchPass.group(1) if self.Pass else None,
                                'password': 'true',
                                'IP': matchlip.group(1) if self.lip else None,
                                'status': 'SUCCESS', 
                                'domain': search_canaries.search_canary(matchMail2.group(1))[1][search_canaries.search_canary(matchMail2.group(1))[2]['uuid']],
                                'site': search_canaries.search_canary(matchMail2.group(1))[0][search_canaries.search_canary(matchMail2.group(1))[2]['uuid']],
                                'testing': search_canaries.search_canary(matchMail2.group(1))[2]['testing'] })
                except:
                    logger.warning({'mail': matchMail2.group(1),
                                #'password': matchPass.group(1) if self.Pass else None,
                                'password': 'true',
                                'IP': matchlip.group(1) if self.lip else None,
                                'status': 'SUCCESS',
                                'domain': search_canaries.search_canary(matchMail2.group(1))[1]['details'],
                                'site': search_canaries.search_canary(matchMail2.group(1))[0]['details'],
                                'testing': search_canaries.search_canary(matchMail2.group(1))[2]['testing'] })
            except:
                logger.warning({'mail': matchMail2.group(1),
                            #'password': matchPass.group(1) if self.Pass else None,
                            'password': 'true',
                            'IP': matchlip.group(1) if self.lip else None,
                            'status': 'SUCCESS', 
                            'details': 'NOT a canary' })
                return

        else:
            return 
