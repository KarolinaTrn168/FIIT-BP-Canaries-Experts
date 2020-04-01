import redis 
import json

try:
    r = redis.StrictRedis(host='cubemail.ga', port=6379, password='........')
    #print(r)
    r.ping()
    print('Connected')
except Exception as ex:
    print('Error', ex)
    exit('Failed')

#print(r.keys())
#for x in range(20):
#    print(r.lindex('log_queue', x))


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
logs = []
for x in range(r.llen('log_queue')):
#for x in range(30):
    logs.append(json.loads(r.lindex('log_queue', x), strict=False))
    if logs[x]['program'] == 'dovecot':
         print(logs[x])       
    
    
