import json
print('haloooooo, ja som dalsi')


class Auth:
    def __init__(self):
        print('inicializujem auth')

    def print(self):
        print('pouzivam auth')


#auth = Auth()

with open('config.json', encoding='utf8') as config_file:
        Config = json.load(config_file)

auth = authProvider(username=Config['canaries_api']['username_api'], password=Config['canaries_api']['password_api'])

auth.print()