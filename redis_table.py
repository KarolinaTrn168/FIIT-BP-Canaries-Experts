import json
import redis
import connection_redis

def create_table():
    print('vytvorenie tabulky')


def pridanie_logu(mail, password, IP, array, r):
    array. append([mail, password, IP])
    print('logy su: ', array)

    print('keys are: ', r.keys())
    if r.exists('mail_list', json.dumps({'mail':mail, 'password':password, 'IP':IP})) == False:
        r.rpush('mail_list', json.dumps({'mail':mail, 'password':password, 'IP':IP}))
