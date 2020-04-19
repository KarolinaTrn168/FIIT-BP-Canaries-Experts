import redis
import json


#toto potom do nejakeho konfig filu
def connection_redis():
    with open('config.json', encoding='utf8') as config_file:
        Config = json.load(config_file)
    try:
        r = redis.StrictRedis(host=Config['redis']['host_redis'], port=Config['redis']['port_redis']) #, password=Config['password'])
        #print(r)
        r.ping()
        print('Connected')
    except Exception as ex:
        print('Error', ex)
        exit('Failed')
    return r
