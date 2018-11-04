#!/usr/bin/env python3
import os
import json
from os import curdir, sep
from json.decoder import JSONDecodeError

# filetypes that must commented out in fail2ban ruleset
commentoutdata = ('exe', 'mp3', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'db', 'sqlite', 'sqlite3', 'html', 'lock')

# source jsonfile with list of filetypes
jsonfile = curdir+sep+"endungen.json"

extrastring = """            smbd.*\:\ IP=<HOST>\|.*(?i)locky(_|\s|-)recover(_|\s|-)instructions.*\.(txt|html|url|png|bmp)$
            smbd.*\:\ IP=<HOST>\|.*(?i)Help(_|\s|-)recover(_|\s|-)files.*\.(txt|html|png|url|bmp)$
            smbd.*\:\ IP=<HOST>\|.*(?i)HELP(_|-|\s)DECRYPT.*\.(html|png|txt|url|bmp)$
            smbd.*\:\ IP=<HOST>\|.*(?i)HELP(_|-|\s)YOUR(_|-|\s)FILES.*\.(html|png|txt|url|bmp)$
            smbd.*\:\ IP=<HOST>\|.*(?i)Wie(-|_|\s)zum(-|_|\s)Wiederherstellen(-|_|\s)von(-|_|\s)Dateien.*\.(html|txt)$
            smbd.*\:\ IP=<HOST>\|.*\.(?i)encrypt(ed|)(_|-|\s|.|)(AES|ped|rsa|locked|)$
            smbd.*\:\ IP=<HOST>\|.*(?i)AppData\\Roaming\\System32Work\\adress.*\.TxT$
            smbd.*\:\ IP=<HOST>\|.*\.(?i)hydracrypt(_|-|\s)ID(_|-|\s|)(#|)$
            smbd.*\:\ IP=<HOST>\|.*(?i)hydracrypt(_|-|\s)ID(_|-|\s|)(#|).(url|html|png|txt)$
            smbd.*\:\ IP=<HOST>\|.*(?i)(_|\s|-)H(_|\s|-)e(_|\s|-)l(_|\s|-)p(_|\s|-)RECOVER(_|\s|-)INSTRUCTIONS.*\.(txt|html|png)$
            smbd.*\:\ IP=<HOST>\|.*\.(?i)zzzzzzzzzzzzzzzzzyyy$
            smbd.*\:\ IP=<HOST>\|.*\.(?i)fuck(ed|yourdata|)$
            smbd.*\:\ IP=<HOST>\|.*\.(?i)bleep(YourFiles|)$
            smbd.*\:\ IP=<HOST>\|.*\.(?i)oor.*$
            smbd.*\:\ IP=<HOST>\|.*(?i)your(_|-|\s)files(_|-|\s).*(locked|encrypted).*.(txt|html|url)$
            smbd.*\:\ IP=<HOST>\|.*(?i)decrypt(_|-|\s|allfiles|)(all|readme|your|instructions|instruct|\s|)(_|-|\s|)(files|\s|)*.(txt|html|url|bmp)$
            smbd.*\:\ IP=<HOST>\|.*\.(?i)breaking(_|-|\s|)bad$
"""


class build_config(object):
	def __init__(self, jsonfilepath=None):
		self.data = dict()
		self.file_data = str()
		self.writefilepath = curdir+sep+"fail2ban"+sep+"filter.d"+sep+"samba.conf"
		
		if jsonfilepath:
			self.data.update({'sourcetype': 'json', 'random_list': ''})
			self.read_jsonfile(filedata=jsonfilepath)
		else:
			print("Unknown file type")
			exit(2)
		
		self.build_header()
		self.build_content()
		self.build_footer()
		self.write_file()
		print("file ", self.writefilepath, " created")
	
	def read_jsonfile(self, filedata):
		js = dict()
		with open(filedata) as f:
			js = json.load(f)
		
		# remove doubble entrys
		d = set()
		for x in js.get('list', []):
			d.add(x.lower().strip().rstrip())
		self.data['random_list'] = list(d)
	
	def write_file(self):
		"""
		create samba.conf file with content
		"""
		f = open(self.writefilepath, "w")
		f.write(self.file_data)
		f.close()
	
	def build_header(self):
		header = """# /etc/fail2ban/filter.d/samba.conf
# TeslaCrypt 3 endungen: xxx,ttt,micro,mp3
# .mp3 endung entfernt
# TeslaCrypt 2 endungen: vvv,aaa,abc,ccc,ecc,exx,vvv,xyz,zzz
# Jigsaw endungen: KKK,BTC,Fun
# Jigsaw Datei: Adress.txt unter Roaming\System32Work
# ODCODC zcrypt endungen
# vipasana: cbf
# Goldeneye: uDz2j8mv
#   
[Definition]
failregex = """
		self.file_data = header
	
	def build_footer(self):
		footer = "ignoreregex = \n"
		self.file_data += footer
	
	def clean(self, data):
		d = data.strip().rstrip().replace(',', '')
		return d
	
	def build_content(self):
		data = str()
		c = 0
		for x in self.data.get('random_list', []):
			s = x.split('.')
			if len(s[0]) > 1:
				print("caution = ", s)
			
			s[1] = self.clean(data=s[1])
			if s[1].lower() in commentoutdata:
				self.file_data += "#"
			
			if c < 1:
				self.file_data += "smbd.*\:\ IP=<HOST>\|.*\.(?i)"+s[1].strip().rstrip()+"$\n"
				c += 1
			else:
				self.file_data += "            smbd.*\:\ IP=<HOST>\|.*\.(?i)"+s[1].strip().rstrip()+"$\n"
		
		self.file_data += extrastring
		self.file_data += "\n\n"


# build samba.conf file and safe under fail2ban/filter.d/samba.conf
build_config(jsonfilepath=jsonfile)
