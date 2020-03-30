import redis


#toto potom do nejakeho konfig filu
def connection_db():
    try:
        r = redis.StrictRedis(host='cubemail.ga', port=6379, password='7hA~KR&)tLe@Cbbh|=#dS9xV')
        #print(r)
        r.ping()
        print('Connected')
    except Exception as ex:
        print('Error', ex)
        exit('Failed')
    return r
