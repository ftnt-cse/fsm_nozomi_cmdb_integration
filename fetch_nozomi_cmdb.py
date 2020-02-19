#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Fetches Nozomi CMDN and format it to be ingetsed by FSM device integration
PS: THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND

"""
__author__ = "FSM CSE Team"
__license__ = "GPL"
__version__ = "0.2"
__status__ = "beta"

import argparse
import time
import requests
import textwrap
import json
import os
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import logging
import logging.handlers 
import socket

document_root_folder='/tmp/'
nozomi_cmdb_csv=document_root_folder+'nozomi.csv'

class bcolors:
	OKGREEN = '\033[92m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'

def send_syslog(server,syslog):
	syslogger = logging.getLogger('syslogger')
	syslogger.setLevel(logging.INFO)
	#UDP
	handler = logging.handlers.SysLogHandler(address = (server,514),  socktype=socket.SOCK_DGRAM)
	syslogger.addHandler(handler)
	syslogger.info(syslog)
	syslogger.handlers[0].flush()

def fetch_nozomi_cmdb(server, username, password):
	# Fetches monitored devices within CMDB
	# Args:
	#     server (str)			: Nozomi IP Address
	#     username (str)		: Nozomi admin username ex: super/admin
	#     password (str)		: Nozomi password

	# Returns:
	#	  CMDB in JSON format
	try:

		authentication=HTTPBasicAuth(username, password)
		response = requests.get('https://'+server+'/api/open/query/do?query=assets',verify=False,auth=authentication)
		if response.status_code != 200:
			print(bcolors.FAIL+'"Error occured'+bcolors.ENDC)
			exit()
		else:
			#print(response.content)
			return response.content

	except requests.ConnectionError:
		print(bcolors.FAIL+"Connection error"+bcolors.ENDC)
		exit()
	except requests.ConnectTimeout:
		print(bcolors.FAIL+"Connection timeout"+bcolors.ENDC)
		exit()
	except requests.exceptions.RequestException as e:
		print(bcolors.FAIL+"Error occured: "+ e + bcolors.ENDC)
		sys.exit(1)

def format_item(item):
	return_list=[]
	if type(item) is str:
		return_list.append(item.replace(',',''))
		return_list.append('')
	elif type(item) is list:
		if len(item) > 1:
			return_list.append(item[0].replace(',',''))
			return_list.append('+'.join(item[1:]))
		elif len(item) == 1:
			return_list.append(item[0].replace(',',''))
			return_list.append('')
		else:
			return_list.append('')
			return_list.append('')

	return ",".join(return_list)


def csv_formatter(csv_file,json_buffer):
	# Formats the returned JSON CMDB into CSV
	# Args:
	#		csv_file			: the csv to create
	#		json_buffer			: Nozomi cmdb CSV
	# returns: 
	#		Creates CMDB CSV file

	csv_line=[]
	open(csv_file, 'w').close()										# Empty previous content
	with open(csv_file, 'a') as file:
		file.write('name,level,capture_device,os,vendor,firmware_version,serial_number,product_name,type,appliance_host,appliance_hosts,mac_address,mac_addresses,vlan_id,vlan_ids,mac_vendor,mac_vendors,ip,ips,protocol,protocols,node,nodes,method,time\n')
		#next(f)																	#skip first line
		for item in json_buffer['result']:
			csv_line.append(item['name'].replace(',',''))
			csv_line.append(item['level'].replace(',',''))
			csv_line.append(item['capture_device'].replace(',',''))
			csv_line.append(item['os'].replace(',',''))
			csv_line.append(item['vendor'].replace(',',''))
			csv_line.append(item['firmware_version'].replace(',',''))
			csv_line.append(item['serial_number'].replace(',',''))
			csv_line.append(item['product_name'].replace(',',''))
			csv_line.append(item['type'].replace(',',''))
			csv_line.append(format_item(item['appliance_hosts']))
			csv_line.append(format_item(item['mac_address']))
			csv_line.append(format_item(item['vlan_id']))
			csv_line.append(format_item(item['mac_vendor']))
			csv_line.append(format_item(item['ip']))
			csv_line.append(format_item(item['protocols']))
			csv_line.append(format_item(item['nodes']))
			csv_line.append('NozomiAPI')
			csv_line.append(str(int(round(time.time() * 1000))))

			line=",".join(csv_line)
			file.write(line+'\n')
			del csv_line[:]



def main():
	parser = argparse.ArgumentParser(
	prog='ProgramName',
	formatter_class=argparse.RawDescriptionHelpFormatter,
	epilog=textwrap.dedent('''\
		 This Program fetches CMDB from Nozomi's Central Management Console, fortmat the output as csv to be ingested by FSM
		 '''))
	parser.add_argument('-s', '--server',type=str, required=True, help="Nozomi Central Management Console IP Address (wihout http://)")
	parser.add_argument('-u', '--username',type=str, required=True, help="Central Management Console Username")
	parser.add_argument('-p', '--password',type=str, required=True, help="Central Management Console Password")
	args = parser.parse_args()

	cmdb = json.loads(fetch_nozomi_cmdb(args.server,args.username,args.password))

	csv_formatter(nozomi_cmdb_csv,cmdb)
	send_syslog('127.0.0.1','<127> Nozomi CMDB updated')

if __name__ == '__main__':
	main()
