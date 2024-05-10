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

HOST = "127.0.0.1"
PORT = 14500
SERVICE_URL = "http://{}:{}/".format(HOST, PORT)

DELAY_TIME = 2 * 60 * 60 # hour * minute * second

class Server():

    def __init__(self):
        self.webshell_list = []
        self.app = Flask(__name__)
        self.delay = DELAY_TIME


    def service(self):
        def new_shell(shell: dict):
            shell_obj = {
                "uuid": Server.gen_uuid(),
                "name": shell["name"],
                "path": shell["path"],
                "desc": shell["desc"],
                "status": False
            }
            self.webshell_list.append(shell_obj)
       
        @self.app.route("/add", methods = ['POST'])
        def add_shell():
            shell = request.get_json()
            new_shell(shell)
            return 'success', 200

        @self.app.route("/list", methods=['GET', 'POST'])
        def list_shell():
            return jsonify(self.webshell_list), 200

        @self.app.route("/del", methods=['POST'])
        def del_shell():
            j = request.get_json()
            for i in range(len(self.webshell_list)):
                if self.webshell_list[i]["uuid"] == j["uuid"]:
                    del self.webshell_list[i]
            return 'success', 200

        @self.app.route("/load", methods=['POST'])
        def load_shell():
            shells = request.get_json()
            for s in shells:
                new_shell(s)
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
                    print("[*] {} webshells are on monitor.".format(len(self.webshell_list)))
                    if len(self.webshell_list) == 0:
                        time.sleep(10)
                    else:
                        for i in range(len(self.webshell_list)):
                            try: 
                                resp = requests.get(self.webshell_list[i]["path"], verify=False)
                                if resp.status_code == 200:
                                    flag = True
                                else:
                                    flag = False
                            except Exception:
                                flag = False
                            if self.webshell_list[i]['status'] ^ flag:
                                Server.msg(self.webshell_list[i], flag)
                                self.webshell_list[i]['status'] = flag
                        time.sleep(self.delay)
            thread = threading.Thread(target=run)
            thread.start()

        self.app.run(HOST, PORT)
    


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
    def gen_uuid():
        return str(uuid.uuid4())

    @staticmethod
    def msg(webshell: dict, isOnline: bool, action: str = ""):
        if action == "add":
            title = "💡{0} Add💡".format(webshell["name"])
        else:
            if isOnline:
                title = "✅{0} is Online✅".format(webshell["name"])
            else:
                title = "❌{0} is Offline❌".format(webshell["name"])
        msg = "## {0}\n\n  \n\n**Path**: {1}\n\n**Description**: {2}".format(title, webshell["path"],webshell["desc"])
        body = {
            "msgtype": "markdown",
            "markdown": {
                "title": "# {} is Offline".format(webshell["name"]),
                "text": msg
            }
        }
        (sign, timestamp) = Server.sign_timestamp()
        webhook = DING_WEBHOOK + "&sign=" + sign + "&timestamp=" + timestamp
        resp = requests.post(url=webhook, json=body, verify=False)
        # print(resp.text)


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
