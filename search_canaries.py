import requests
import datetime
from threading import Timer
import json


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
        if not self.token_type or self.token or (not self.expires) or (self.expires and (self.expires < datetime.datetime.now())):
            # posli request na server a skus sa prihlasit
            try:
                r = requests.request(method='post', url='https://canary1.demo-cert.sk/v1/auth/login', data={
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

                        print('Successfully logged in as "%s". Token expires on: %s' % (
                            self.username, self.expires.strftime('%Y-%m-%d %H:%M:%S')))
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
            r = requests.request(method='post', url='https://canary1.demo-cert.sk/v1/auth/refresh_token',
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


# vytvoris si instanciu AuthProvidera:
def open_config():
    with open('config.json', encoding='utf8') as config_file:
        Config = json.load(config_file)
    return Config

def authorization(authProvidor):
    Config = open_config()
    auth = authProvider(username=Config['canaries_api']['username_api'], password=Config['canaries_api']['password_api'])
    return auth

def search_canary(mail):
    auth = authorization(authProvider)
    Config = open_config()

    try:
        r = requests.get(url=Config['canaries_api']['url_api'] + '/' + Config['canaries_api']['version_api'] + '/canaries', params={
            'email': mail
        }, headers=auth.getHeader())

        data = r.json()
        print(data)

    except Exception as error:
        print('Error: %s' % error)
        exit

#search_canary()