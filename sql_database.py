import peewee
from peewee import *
import json
from datetime import datetime

def connect_sql():
    with open('config.json', encoding='utf8') as config_file:
        Config = json.load(config_file)

    db = peewee.MySQLDatabase(Config['mysql']['db_sql'], host=Config['mysql']['host_sql'], user=Config['mysql']['user_sql'], passwd=Config['mysql']['password_sql'], charset='utf8mb4')
    return db

class Mail_Passwd_IP(peewee.Model):
    id = peewee.BigAutoField(unique=True, index=True, primary_key=True)
    mail = peewee.CharField()
    password = peewee.CharField()           #trying password 
    IP = peewee.CharField()
    time = DateTimeField()

    class Meta:
        database = connect_sql() 
        table_name = 'Mail_Passwd_IP'    


def mail_information(mail, password, IP, time):
    db = connect_sql()

    if db.is_closed():
        db.connect()
    
    query = Mail_Passwd_IP.select().where(Mail_Passwd_IP.mail == mail and Mail_Passwd_IP.password == password and Mail_Passwd_IP.IP == IP)
    print('query:', query)
    if Mail_Passwd_IP.select().where(Mail_Passwd_IP.mail == mail and Mail_Passwd_IP.password == password and Mail_Passwd_IP.IP == IP):
        if not db.is_closed():
           db.close()
        print('uz je')
        return 1
    else:    
        print('je to:', mail, password, IP, time)
        Mail_Passwd_IP.insert(mail=mail, password=password, IP=IP, time=datetime.fromtimestamp(time)).execute()

    if not db.is_closed():
            db.close()
