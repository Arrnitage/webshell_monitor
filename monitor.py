import requests
import json
from flask import Flask, request,jsonify
import sys
import time
import hmac
import hashlib
import base64
import urllib.parse
import uuid
import threading
import urllib3
urllib3.disable_warnings()

VERSION = "v0.1.0"

## DINGDING_WEBHOOK = "https://oapi.dingtalk.com/robot/send?access_token=XXXXXXXXXXXXXXXXXXXXXXXX"
DING_WEBHOOK = ""
## DINGDING_SECRET = "SECXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
SECRET = ''

# SERVICE CONFIG
HOST = "127.0.0.1"
PORT = 14500
SERVICE_URL = "http://{}:{}/".format(HOST, PORT)

# CONST
DELAY_TIME = 2 * 60 * 60 # hour * minute * second
MSG_TEMPLATE_1 = "## {0}\n\n  \n\n**Path**: {1}\n\n**Description**: {2}"



class Shell():
    def __init__(self, name: str, path: str, desc: str) -> None:
        self.uuid = Utils.gen_uuid()
        self.name = name
        self.path = path
        self.desc = desc
        self.status = False

    def to_dict(self) -> dict:
        shell= {
                "uuid": self.uuid,
                "name": self.name,
                "path": self.path,
                "desc": self.desc,
                "status": self.status
            }
        return shell
    

class Utils():
    @staticmethod
    def gen_uuid():
        return str(uuid.uuid4())

    @staticmethod
    def sign_timestamp():
        timestamp = str(round(time.time() * 1000))
        secret_enc = SECRET.encode('utf-8')
        string_to_sign = '{}\n{}'.format(timestamp, SECRET)
        string_to_sign_enc = string_to_sign.encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        return (sign, timestamp)
    
    @staticmethod
    def send_msg(msg: str):
  
        body = {
            "msgtype": "markdown",
            "markdown": {
                "title": "",
                "text": msg
            }
        }
        (sign, timestamp) = Utils.sign_timestamp()
        webhook = DING_WEBHOOK + "&sign=" + sign + "&timestamp=" + timestamp
        resp = requests.post(url=webhook, json=body, verify=False)
        # print(resp.text)
    

class Server():

    def __init__(self):
        self.shell_list: list[Shell] = []
        self.app = Flask(__name__)
        self.delay = DELAY_TIME


    def service(self):
        
        def alive_msg(webshell: Shell, isOnline: bool):
            if isOnline:
                title = "🟢{0} is Online🟢".format(webshell.name)
            else:
                title = "🔴{0} is Offline🔴".format(webshell.name)
            msg = MSG_TEMPLATE_1.format(title, webshell.path, webshell.desc)
            Utils.send_msg(msg)
       
        @self.app.route("/add", methods = ['POST'])
        def add_shell():
            shell = request.get_json()
            shell_obj = Shell(shell["name"], shell["path"], shell["desc"])
            self.shell_list.append(shell_obj)
            title = "✅{0} Add✅".format(shell_obj.name)
            msg = MSG_TEMPLATE_1.format(title, shell_obj.path, shell_obj.desc)
            Utils.send_msg(msg=msg)
            return 'success', 200

        @self.app.route("/list", methods=['GET', 'POST'])
        def list_shell():
            webshell_list = []
            for shell in self.shell_list:
                webshell_list.append(shell.to_dict())
            return jsonify(self.shell_list), 200

        @self.app.route("/del", methods=['POST'])
        def del_shell():
            j = request.get_json()
            
            for i in range(len(self.shell_list)):
                if self.shell_list[i].uuid == j["uuid"]:
                    title = "❌{0} Delete❌".format(self.shell_list[i].name)
                    msg = MSG_TEMPLATE_1.format(title, self.shell_list[i].path, self.shell_list[i].desc)
                    Utils.send_msg(msg=msg)
                    del self.shell_list[i]
            return 'success', 200

        @self.app.route("/load", methods=['POST'])
        def load_shell():
            shells = request.get_json()
            for s in shells:
                webshell = Shell(s["name"], s["path"], s["desc"])
                self.shell_list.append(webshell)
            return 'success', 200
        
        @self.app.route("/delay", methods=["POST"])
        def delay():
            delay_time = request.get_json()
            self.delay = delay_time['secs']
            return 'success', 200
        
        @self.app.before_first_request
        def check_alive():
            def run():
                while(True):
                    print("[*] {} webshells are on monitor.".format(len(self.shell_list)))
                    if len(self.shell_list) == 0:
                        time.sleep(10)
                    else:
                        for i in range(len(self.shell_list)):
                            try: 
                                resp = requests.get(self.shell_list[i].path, verify=False)
                                if resp.status_code == 200:
                                    flag = True
                                else:
                                    flag = False
                            except Exception:
                                flag = False
                            if self.shell_list[i].status ^ flag:
                                alive_msg(self.shell_list[i], flag)
                                self.shell_list[i].status = flag
                        time.sleep(self.delay)
            thread = threading.Thread(target=run)
            thread.start()

        self.app.run(HOST, PORT)
    



class Client():
    @staticmethod
    def list_shell():
        resp = requests.get(SERVICE_URL + "list", verify=False)
        if resp.status_code == 200:
            print(json.dumps(json.loads(resp.text), indent=4))
            print("[+] Success")

    @staticmethod
    def add_shell(name: str = "", path: str = "", desc: str = ""):
        if name == "" or path == "" or desc == "":
            name = input("[*] Name: ")
            path = input("[*] Path: ")
            desc = input("[*] Desc: ")
        body = {
            "name": name,
            "path": path,
            "desc": desc,
        }
        resp = requests.post(SERVICE_URL + "add", json=body, verify=False)
        if resp.status_code == 200:
            print("[+] Success")

    @staticmethod
    def del_shell(uuid: str = ""):
        if uuid == "":
            uuid = input("[*] UUID: ")
        body = {
            "uuid": uuid
        }
        resp = requests.post(SERVICE_URL + "del", json=body, verify=False)
        if resp.status_code == 200:
            print("[+] Success")

    @staticmethod
    def load_shell(config: str):
        with open(config, "r") as f:
            config_json = f.read()
        webshell_list = json.loads(config_json)
        
        resp = requests.post(SERVICE_URL + "load", json=webshell_list, verify=False)
        if resp.status_code == 200:
            print("[+] Success")

    @staticmethod
    def delay(sec: int):
        body = {
            "secs": sec
        }
        resp = requests.post(SERVICE_URL + "delay", json=body, verify=False)
        if resp.status_code == 200:
            print("[+] Success" )


def help():
    print("""

 _____________________
< Oh!webshell Online! >
 ---------------------
        \   ^__^
         \  (oo)\_______      @Author: Arm!tage
            (__)\       )\/\  @Version: {ver}
                ||----w |
                ||     ||

USAGE:
    Run Service
        python3 {script} server

    Use Client
        python3 {script} list
        python3 {script} add [<name> <path> <description>]
        python3 {script} del [uuid]
        pyhton3 {script} load <config file>
        python3 {script} delay <seconds>
        
    Export
        curl -k http://{host}:{port}/list
""".format(script=sys.argv[0], host=HOST, port=PORT, ver=VERSION))
    exit()

def main():
    cmd = sys.argv[1]
    if cmd == "-h" or cmd == "--help":
        help()
    if  cmd == "server":
        print("[+] Start Monitor Service")
        Server().service()
    if cmd == "list":
        print("[+] List Webshell")
        Client.list_shell()
    if cmd == "add":
        print("[+] Add Webshell")
        try:
            Client.add_shell(sys.argv[2], sys.argv[3], sys.argv[4])
        except Exception:
            Client.add_shell()   
    if cmd == "del":
        print("[+] Delete Webshell")
        try:
            Client.del_shell(sys.argv[2])
        except Exception:
            Client.del_shell()
    if cmd == "load":
        print("[+] Load Webshell file")
        config_file = sys.argv[2]
        Client.load_shell(config_file)
    if cmd == "delay":
        print("[+] Change delay seconds")


if __name__ == "__main__":
    main()
