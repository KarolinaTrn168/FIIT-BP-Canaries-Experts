import redis 
import json

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


#for x in range(50):
#    print(r.lindex('log_queue', x))

with open('logs.txt', 'w') as file:
    #for x in range(50):
    for x in range(r.llen('log_queue')):
        json.dump((json.loads(r.lindex('log_queue', x), strict=False)), file)
        file.write('\n')     



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
    