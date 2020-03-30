import json
import random
import redis 

import experts
import connection

#spojenie s redis
r = connection.connection_db()

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

#registrovanie potrebnych expertov 
registerExpert(experts.DovecotExpert)
registerExpert(experts.IMAPExpert)
registerExpert(experts.PostfixExpert)



#toto mozno extra.. 
#vyberanie logov
def getLog():    
    logs = []
    for x in range(50):
        logs.append(json.loads(r.lindex('log_queue', x), strict=False))
    #print(logs)
    return logs
   
#zatial berie vsetky logy, ktore dam do logs... neskor by mal tahat logy, vzdy ked pridu nove 
logy = getLog()
while logy:
    log = logy[0]
    for e in modules:       #posle log kazdemu expertovi
        if log['program'] in e['types']:        #ak expert akceptuje typ programu, dany expert recievne log a tam ho spracuje             
            e['class'].receive(log)
    logy.remove(logy[0])        #vymazem poslany log z logov 
