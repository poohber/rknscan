#!/usr/bin/python
# -*- coding: utf-8 -*-

from suds.client import Client
from base64 import b64decode
from time import gmtime, strftime, sleep
import datetime
import sys
from termcolor import colored
import colorama

rkn_url = "https://vigruzki2.rkn.gov.ru/services/OperatorRequest2/?wsdl"
RKN_START_LOG = "rkn_start_log"
colorama.init()

if len(sys.argv) < 2:
	print(colored('Для доступа к базе РКН необходимо первым аргументом ввести логин, вторым пароль для доступа к базам.', "green"))
	# exit(0)
	rkn_login = input("Введите логин для доступа к базе РКН: ")
	rkn_pass = input("Введите пароль для доступа к базе РКН: ")
elif sys.argv[1].lower() == "help" or sys.argv[1].lower() == "-h" or sys.argv[1] == "--help" or sys.argv[1].lower() == "-help":
	print(colored('Для доступа к базе РКН необходимо первым аргументом ввести логин, вторым пароль для доступа к базам.', "green"))
	exit(0)
elif len(sys.argv) < 3:
	print(colored('Для доступа к базе РКН необходимо первым аргументом ввести логин, вторым пароль для доступа к базам.', "green"))
	exit(0)
else:
	rkn_login = sys.argv[1]
	rkn_pass = sys.argv[2]


def get_suds_client():
    reconnect_count = 0
    SUDS_RECONNECT_COUNT = 5
    client = False
    print(colored("RKN_URL: " + rkn_url, "yellow"))
    print(colored("RKN_USER: " + rkn_login, "yellow"))
    print(colored("RKN_PASS: " + rkn_pass, "yellow"))

    while True and reconnect_count < SUDS_RECONNECT_COUNT:
        try:
            try:
                client = Client(rkn_url, username=rkn_login, password=rkn_pass)
            except suds.transport.TransportError as mess:
                start_log("Suds.error:"+str(mess))
                start_log(colored("WARN: Can't connect: RKN_SRV send TCP connection reset. Reconnecting..", "red"))
                sleep(1)
                reconnect_count +=1
                continue
            except:
                start_log("WARN: Can't connect: RKN_SRV send TCP connection reset. Reconnecting..", "red")
                sleep(1)
                reconnect_count +=1
                continue
        except Exception as c:
            print(colored('ALARM! Suds client got new unknown exception!', "red"))
            print(colored('Suds exception:' + str(c), "red"))
        break
    if client:
        return client
    else:
        start_log(colored("ERR: suds.Client couldn't connect and exit()", "red"))
        exit()

def get_full_xml_dump():
	reconnect_count = 0
	SUDS_RECONNECT_COUNT = 5
	while True and reconnect_count < SUDS_RECONNECT_COUNT:
		try:
			try:
				client = get_suds_client()
				vigruzka = client.service.getResult()
			except:
				start_log(colored("WARN: Can't connect: RKN_SRV send TCP connection reset. Reconnecting..", "red"))
				sleep(1)
				reconnect_count +=1
				continue
		except Exception as c:
			print('ALARM! Suds client got new unknown exception!')
			print('Suds exception:' + str(c))
		break
	try:
		with open('result.zip', "wb") as f:
			f.write(b64decode(vigruzka['registerZipArchive']))
	except UnboundLocalError:
		start_log(colored("ERROR: Reconnect count finished..", "red"))
		exit(0)
	import zipfile
	zip_file = zipfile.ZipFile('result.zip', 'r')
	zip_file.extract('dump.xml')
	start_log(colored("get_full_xml_dump(): full dump downloaded and placed to dump.xml", "green"))

def start_log(message):
    """
    :param message:
    :type message:
    """
    print(message)
    log = open(RKN_START_LOG, "a")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S ")
    log.write(timestamp + message+"\n")
    log.close()

if __name__ == '__main__':
	get_full_xml_dump()
