import redis 
import re 
import json
import base64

with open('config.json', encoding='utf8') as config_file:
        Config = json.load(config_file)
try:
    r = redis.StrictRedis(host=Config['redis']['host_redis'], port=Config['redis']['port_redis'])
    #print(r)
    r.ping()
    print('Connected')
except Exception as ex:
    print('Error', ex)
    exit('Failed')

print(r.keys())
#r.set('mail_list', 0)
#print(r.keys())
#r.lpop('mail_list')


# r.delete('mail_list')
# print(r.keys())


for x in range(r.llen('mail_list')):
    print(r.lindex('mail_list', x))

# base64_message = 'AGNvbWJpbmVkQGN1YmVtYWlsLmdhAHRlc3Q'
# base64_message += "=" * ((4 - len(base64_message) % 4) % 4)
# base64_bytes = base64_message.encode('ascii')
# message_bytes = base64.b64decode(base64_bytes)
# message = message_bytes.decode('ascii')
# print(message)




# self.Mail = re.compile(r'(?:\.?)([\w\-_+#~!$&\'\.]+(?<!\.)(@|[ ]?\(?[ ]?(at|AT)[ ]?\)?[ ]?)(?<!\.)[\w]+[\w\-\.]*\.[a-zA-Z-]{2,3})(?:[^\w])')
# matchMail = self.Mail.search('AGNvbWJpbmVkQGN1YmVtYWlsLmdhAHRlc3Q')

# with open('logs.txt', 'w') as file:
#     #for x in range(50):
#     for x in range(r.llen('log_queue')):
#         json.dump((json.loads(r.lindex('log_queue', x), strict=False)), file)
#         file.write('\n')     



#zistenie, ake programy su v logoch - vytvorenie expertov 
#programs = []
#logs = []
#for x in range(r.llen('log_queue')):
#    logs.append(json.loads(r.lindex('log_queue', x), strict=False))
#    if logs[x]['program'] not in programs:
#        programs.append(logs[x]['program'])
#print(programs)

#programs: dovecot, postfix/smtpd, postfix/anvil, postfix/smtps/smtpd, postfix/submission/smtpd, postfix/cleanup, postfix/qmgr, postfix/lmtp, postfix/scache, 
# postfix/bounce, postfix/error, postfix/postfix-script, postfix/master


#zistenie, co je v logoch 
#logs = []
#with open('logs.txt', 'w') as file:
#for x in range(r.llen('log_queue')):
#    for x in range(10000):
#        logs.append(json.loads(r.lindex('log_queue', x), strict=False))
#        if logs[x]['program'] == 'dovecot':
#            #print(logs[x])  
#            json.dump(logs[x], file)
#            file.write('\n')     
    

#logs = []
#with open('postfix.txt', 'w') as file1:
    #for x in range(r.llen('log_queue')):
#    for x in range(100):
#        logs.append(json.loads(r.lindex('log_queue', x), strict=False))
#        if 'postfix' in logs[x]['program']:
            #print(logs[x])  
#            json.dump(logs[x], file1)
#            file1.write('\n')     
    