import peewee
from peewee import *
import json
from datetime import datetime
import search_canaries

def connect_sql():
    with open('config.json', encoding='utf8') as config_file:
        Config = json.load(config_file)

    db = peewee.MySQLDatabase(Config['mysql']['db_sql'], host=Config['mysql']['host_sql'], user=Config['mysql']['user_sql'], passwd=Config['mysql']['password_sql'], charset='utf8mb4')
    return db

class SMTP(peewee.Model):
    id = peewee.BigAutoField(unique=True, index=True, primary_key=True)
    time = peewee.DateTimeField()
    mail = peewee.CharField()
    try_password = peewee.CharField()            
    IP = peewee.CharField()
    status = peewee.CharField()
    method = peewee.CharField()
    service = peewee.CharField()

    class Meta:
        database = connect_sql() 
        table_name = 'SMTP'    

class IMAP(peewee.Model):
    id = peewee.BigAutoField(unique=True, index=True, primary_key=True)
    time = peewee.DateTimeField()
    mail = peewee.CharField()           #contains sensitive data
    password = peewee.CharField()            
    Lip = peewee.CharField()
    Rip = peewee.CharField()
    LPort = peewee.IntegerField()
    RPort = peewee.IntegerField()
    status = peewee.CharField()
    service = peewee.CharField()
    method = peewee.CharField()

    class Meta:
        database = connect_sql() 
        table_name = 'IMAP'

def mail_information(mail, password, IP, time):
    db = connect_sql()

    if db.is_closed():
        db.connect()
    
    query = SMTP.select().where(SMTP.mail == mail and SMTP.try_password == password and SMTP.IP == IP)
    print('query:', query)    #IP prazdne
    if SMTP.select().where(SMTP.mail == mail and SMTP.try_password == password and SMTP.IP == IP):
        if not db.is_closed():
           db.close()
        print('uz je')
        return 1
    else:    
        print('je to:', mail, password, IP, time)
        SMTP.insert(mail=mail, try_password=password, IP=IP, time=datetime.fromtimestamp(time)).execute()
        search_canaries.search_canary(mail)

    if not db.is_closed():
            db.close()
