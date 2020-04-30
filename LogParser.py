import json
import random
import redis 
import experts
import connection_redis
import search_canaries


#spojenie s redis
r = connection_redis.connection_redis()
print(r.keys())

with open('config.json', encoding='utf8') as config_file:
        Config = json.load(config_file)

# auth = search_canaries.authorization(search_canaries.authProvider)
# auth = authProvider(username=Config['canaries_api']['username_api'], password=Config['canaries_api']['password_api'])

#zoznam expertov, ktory su zaregistrovany
modules = []
#zoznam notifikacnych kanalov - email, sms, SIEM, push notifikacie  -- zatial neriesim 
#notify_channels = []

#registrovanie experta
def registerExpert(cls):
    modules.append({
        'class': cls(siemMessage),      #instancovanie triedy experta a nastavenie funkcie
        'types': cls.accepted_programs      #akceptovane programy z experta
    })
    print('Registered: ' + str(cls.__name__))

#informuj koho treba..
def siemMessage(message):
    print(message)
    # json.dump(message, file1)
    # file1.write('\n') 

registerExpert(experts.DovecotExpert) 
registerExpert(experts.PostfixExpert)

#toto mozno extra.. 
#vyberanie logov
def getLog():    
    logs = []
    #for x in range(r.llen('log_queue')):
    for x in range(50):
        try:
            logs.append(json.loads(r.lindex('log_queue', x), strict=False))
        except:
            print(r.lindex('log_queue', x))
    #print(logs)
    return logs
   
#zatial berie vsetky logy, ktore dam do logs... neskor by mal tahat logy, vzdy ked pridu nove 
file = open('all_logs.txt', 'w')
logy = getLog()
while logy:
    log = logy[0] 
    json.dump(log, file)
    file.write('\n')
    r.rpush('mail_list', json.dumps({'time':log['time'], 'message':log['message'], 'program':log['program']}))
    for e in modules:       #posle log kazdemu expertovi
        if log['program'] in e['types']:        #ak expert akceptuje typ programu, dany expert recievne log a tam ho spracuje             
            e['class'].receive(log, r)
    logy.remove(logy[0])        #vymazem poslany log z logov 
