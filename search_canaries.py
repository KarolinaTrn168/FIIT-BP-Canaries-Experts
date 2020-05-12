import requests
import datetime
from threading import Timer
import json

with open('config.json', encoding='utf8') as config_file:
    Config = json.load(config_file)

class authProvider:
    username = None
    password = None
    token_type = None
    token = None
    expires = None
    timer = None

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def tryLogin(self):
        # token_type neexistuje alebo token neexistuje alebo expires neexistuje alebo cas uz vyprsal - teda token je neplatny - treba novy
        if not self.token_type or not self.token or (not self.expires) or (self.expires and (self.expires < datetime.datetime.now())):
            # posli request na server a skus sa prihlasit
            try:
                r = requests.request(method='post', url=Config['canaries_api']['url_api'] + '/' + Config['canaries_api']['version_api'] + '/auth/login', data={
                    'username': self.username,
                    'password': self.password
                })
                data = r.json()

                if r.status_code == 200:
                    try:
                        self.token_type = data['token_type']
                        self.token = data['token']
                        #casova znacka prave teraz + sekundy do expiracie - 5 sekund rezerva
                        self.expires = datetime.datetime.now(
                        ) + datetime.timedelta(seconds=(data['expires'] - 5))

                        #zastav stary timer, nastav novy timer, ktory spusti automaticke obnovovanie tokenu
                        if self.timer and self.timer.isAlive():
                            self.timer.cancel()
                        self.timer = Timer(
                            data['expires'] - 5, self._refreshToken)
                        self.timer.start()

                        print('Successfully logged in. Token expires on: %s' % (self.expires.strftime('%Y-%m-%d %H:%M:%S')))
                    except:
                        raise

                elif r.status_code == 429:
                    raise Exception('Too many login attempts!')

                else:
                    raise Exception('Invalid credentials')

            #nepodarilo sa ani len zavolat request na API
            except:
                raise
                #raise Exception('Cannot connect - login')

    #obnovenie token predtym ako vyprsi
    def _refreshToken(self):
        try:
            r = requests.request(method='post', url=Config['canaries_api']['url_api'] + '/' + Config['canaries_api']['version_api'] + '/auth/refresh_token',
                                 headers={'Authorization': '%s %s' % (self.token_type, self.token)})
            data = r.json()
            try:
                self.token_type = data['token_type']
                self.token = data['token']
                self.expires = datetime.datetime.now(
                ) + datetime.timedelta(seconds=(data['expires'] - 5))
                if self.timer and self.timer.isAlive():
                    self.timer.cancel()
                self.timer = Timer(data['expires'] - 5, self._refreshToken)
                self.timer.start()
            except:
                print('Something bad happened')
                exit
        except:
            print('Cannot connect')
            exit

    def getHeader(self):
        # prihlasenie sa na server
        try:
            self.tryLogin() 
        except:
            raise
        #vrat header pre dalsie requesty
        return {'Authorization': '%s %s' % (self.token_type, self.token)}

    def __del__(self):
        if self.timer and self.timer.isAlive():
            self.timer.cancel()

# vytvoris si instanciu AuthProvidera:
def authorization(authProvider):
    auth = authProvider(username=Config['canaries_api']['username_api'], password=Config['canaries_api']['password_api'])
    return auth

def search_canary(mail):
    token = auth.getHeader()

    try:
        r = requests.get(url=Config['canaries_api']['url_api'] + '/' + Config['canaries_api']['version_api'] + '/canaries', params={
            'email': mail
        }, headers=token)

        data = r.json()
        #print(data)
        try:
            if data['details'] == 'Canary does not exist':      #canary does not exist
                return data
        except:
            if data['testing'] == False:           #canary is not a testing one
                uuid = data['uuid']
                try:
                    t = requests.get(url=Config['canaries_api']['url_api'] + '/' + Config['canaries_api']['version_api'] + '/sites' + '/' + uuid , headers=token)
                    sites = t.json()
                except Exception as error:
                    print('Error: %s' % error)
                    exit
                try:
                    t = requests.get(url=Config['canaries_api']['url_api'] + '/' + Config['canaries_api']['version_api'] + '/domains' + '/' + uuid , headers=token)
                    domains = t.json()
                except Exception as error:
                    print('Error: %s' % error)
                    exit
                return [sites, domains, data]

            elif data['testing'] == True:       #canary is a testing one
                uuid = data['uuid']
                try:
                    t = requests.get(url=Config['canaries_api']['url_api'] + '/' + Config['canaries_api']['version_api'] + '/sites' + '/' + uuid , headers=token)
                    sites = t.json()
                except Exception as error:
                    print('Error: %s' % error)
                    exit                
                try:
                    t = requests.get(url=Config['canaries_api']['url_api'] + '/' + Config['canaries_api']['version_api'] + '/domains' + '/' + uuid , headers=token)
                    domains = t.json()
                except Exception as error:
                    print('Error: %s' % error)
                    exit
                return [sites, domains, data]

    except Exception as error:
        print('Error: %s' % error)
        exit


#search_canary('Ivan.Kral@cloudmail.ga')[0][search_canary('Ivan.Kral@cloudmail.ga')[2]['uuid']]

auth = authorization(authProvider)
#print(search_canary('benesrene@cloudmail.ga')[2])
#print(search_canary('Ivan.Kral@cloudmail.ga')[2])



# if search_canary('Ivan.Kral@cloudmail.ga') == 0:
#      print('NOPE')
# elif search_canary('Ivan.Kral@cloudmail.ga') == 1:
#      print('YES')
# else:
#     print('neexistuje.')
