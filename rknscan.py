#! /usr/bin/python3
#-*- coding: utf-8 -*-
#from urllib import urlopen
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from random import choice
import re
from optparse import OptionParser
from threading import Thread, Lock
import socket
import requests
import string
import time
import os
import dns.resolver
import dns.exception
import colorama
from termcolor import colored
from netaddr import IPNetwork
from queue import Queue, Empty
from requests.exceptions import ConnectionError
import logging
from color_log import log

# Logging settings
# FORMAT = '%(asctime)s: %(levelname)s: %(message)s' #add time annd name of log verbose
FORMAT = '%(message)s'
logging.basicConfig(level=logging.INFO, format=FORMAT ) # , filename='rknscan.log'
logging.getLogger("urllib3").setLevel(logging.WARNING) #turn off urlib logging
logging.getLogger("requests").setLevel(logging.WARNING)
#turn on coloring on windows
colorama.init()

parser = OptionParser()
parser.add_option("-r", "--regexp", dest="regexp", help="Установить регулярное выражение, по которому будет матчиться вывод открываемой страницы (тут необходимо указать какой-либо кусок со страницы заглушки)")
parser.add_option("-v", "--verbose", dest="verbose", help="Увеличить вербозность (для дебага)", action="store_true")
parser.add_option("-n", "--numthreads", dest="n_threads", help="Установить количество потоков (defaul=500)")
parser.add_option("-i", "--numipthreads", dest="n_ip_threads", help="Установить количество потоков (defaul=200)")
parser.add_option("-t", "--timeout", dest="timeout", help="Таймаут по истечению которого неответивший сайт считается недоступным (default=3)")
parser.add_option("-f", "--file", dest="file", help="Указать файл с перечнем URL для проверки (НЕ в случае реестра Роскомнадзора)")
parser.add_option("-s", "--substituteip", dest="substitute", help="Добавление в выборку URL адресов, с замененным доменом на IP адрес (в случае реестра Роскомнадзора)", action="store_true")
parser.add_option("-c", "--console", dest="console", help="Запуск в консольном режиме (без интерактива)", action="store_true")

(options, args) = parser.parse_args()

regexp = "logo_eco.png" if not options.regexp else options.regexp
timeout = 3 if not options.timeout else int(options.timeout)
n_threads = 500 if not options.n_threads else int(options.n_threads)
n_ip_threads = 200 if not options.n_ip_threads else int(options.n_ip_threads)
verbose = 0 if not options.verbose else int(options.verbose)
f = '' if not options.file else options.file
substitute = options.substitute

if options.timeout:options.timeout=float(options.timeout)


def query_yes_no(question, default="yes"):
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        print(question + prompt, end="")
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print(colored("Пожалуйста введите 'yes' или 'no' "
                             "(или 'y' или 'n').", 'red'))

if not options.console:
    regexp = input("Введите регулярное выражение для поиска на странице-заглушке: ")
    timeout = input("Введите таймаут по истечению которого неответивший сайт будет считаться недоступным (3): ")
    n_threads = input("Введите количество потоков (500): ")
    n_ip_threads = input(("Введите количество потоков для проверки blocktype_ip (200): "))
    f =  input("Введите имя файла для проверки (пусто если проверяем реестр РКН): ")
    substitute = query_yes_no("Добавлять в выборку url с заменой domain на ip адрес ресурса?")

    verbose = 0
    regexp = "logo_eco.png" if regexp=='' else regexp
    timeout = 3 if not timeout else int(timeout)
    n_threads = 500 if not n_threads else int(n_threads)
    n_ip_threads = 200 if not n_ip_threads else int(n_ip_threads)

dns_records_list = {"rutracker.org": ['195.82.146.214'],
                    "grani.org": ['72.52.4.120'],
                    "e621.net": ['104.24.11.70', '104.24.10.70'],
                    "ipvnews.org": ['85.31.101.152']
                    }

dpi_list =   {
            'rutracker.org':
               {'host': 'rutracker.org', 'urn': '/forum/index.php',
                'lookfor': 'groupcp.php"', 'ip': '195.82.146.214'},
              'ipvnews.org':
                {'host': 'ipvnews.org', 'urn': '/hegemon.php',
                 'lookfor': 'pandora.php', 'ip': '85.31.101.152'},
             }

google_dns = '8.8.4.4'

urlregex = re.compile(
                r'^((?:http|https|newcamd525|mgcamd525)://)?' # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
                r'localhost|' #localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
                r'(?::\d+)?' # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)




def _decode_bytes(input_bytes):
    return input_bytes.decode(errors='replace')

def _get_a_record(site, timeout=3, dnsserver=None):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    if dnsserver:
        resolver.nameservers = [dnsserver]

    result = []
    while len(resolver.nameservers):
        try:
            try:
                answer=resolver.query(site)
            except Exception as e:
                #print(" Невозможно зарезолвить сайт: "+site)
                return False
            for item in answer.rrset.items:
                item = item.to_text()
                if '#' in item:
                    hex_data = item.split(" ")[2]
                    item="%i.%i.%i.%i" % (int(hex_data[0:2],16),int(hex_data[2:4],16),int(hex_data[4:6],16),int(hex_data[6:8],16))
                if (not IPNetwork(item).is_loopback()):
                   result.append(item)
            return result

        except dns.exception.Timeout:
            resolver.nameservers.remove(resolver.nameservers[0])

    # If all the requests failed
    return False

def _get_a_records(sitelist, timeout, dnsserver=None):
    result = []
    for site in sitelist:
        try:
            records = _get_a_record(site, timeout, dnsserver)
            if not records:
                log.warning(f'No DNS answer! Return False')
                return False
            for item in records:
                result.append(item)
        except dns.resolver.NXDOMAIN:
            log.warning(f"[!] Невозможно получить DNS-запись для домена {site} (NXDOMAIN). Результаты могут быть неточными.")
        except dns.exception.DNSException:
            return ""
    return sorted(result)

def _dpi_send(host, port, data, fragment_size=0, fragment_count=0):
    sock = socket.create_connection((host, port), 10)
    if fragment_count:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    try:
        for fragment in range(fragment_count):
            sock.sendall(data[:fragment_size].encode())
            data = data[fragment_size:]
        sock.sendall(data.encode())
        recvdata = sock.recv(8192)
        recv = recvdata
        while recvdata:
            recvdata = sock.recv(8192)
            recv += recvdata
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        sock.close()
    return _decode_bytes(recv)

def _dpi_build_tests(host, urn, ip, lookfor):
    dpi_built_list = \
        {'дополнительный пробел после GET':
                {'data': "GET  {} HTTP/1.0\r\n".format(urn) + \
                        "Host: {}\r\nConnection: close\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
            'дополнительный пробел после urn':
                {'data': "GET {}  HTTP/1.0\r\n".format(urn) + \
                        "Host: {}\r\nConnection: close\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
            'дополнительный пробел после HTTP/1.0':
                {'data': "GET {} HTTP/1.0 \r\n".format(urn) + \
                        "Host: {}\r\nConnection: close\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
            'нестандартная версия HTTP':
                {'data': "GET {}  HTTP/123.456\r\n".format(urn) + \
                        "Host: {}\r\nConnection: close\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
            'фрагментирование заголовка':
                {'data': "GET {} HTTP/1.0\r\n".format(urn) + \
                        "Host: {}\r\nConnection: close\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 2, 'fragment_count': 6},
            'точка в конце домена':
                {'data': "GET {} HTTP/1.0\r\n".format(urn) + \
                        "Host: {}.\r\nConnection: close\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
            'заголовок host вместо Host':
                {'data': "GET {} HTTP/1.0\r\n".format(urn) + \
                        "host: {}\r\nConnection: close\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
            'перенос строки в заголовках в UNIX-стиле':
                {'data': "GET {} HTTP/1.0\n".format(urn) + \
                        "Host: {}\nConnection: close\n\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
            'необычный порядок заголовков':
                {'data': "GET {} HTTP/1.0\r\n".format(urn) + \
                        "Connection: close\r\nHost: {}\r\n\r\n".format(host),
                'lookfor': lookfor, 'ip': ip,
                'fragment_size': 0, 'fragment_count': 0},
        }
    return dpi_built_list

def test_dpi():
    log.info("[O] Тестируем обход DPI")

    dpiresults = []
    for dpisite in dpi_list:
        site = dpi_list[dpisite]
        dpi_built_tests = _dpi_build_tests(site['host'], site['urn'], site['ip'], site['lookfor'])
        for testname in dpi_built_tests:
            test = dpi_built_tests[testname]
            log.info(colored(f"\tПробуем способ \"{testname}\" на {dpisite}", "white"))
            try:
                result = _dpi_send(test.get('ip'), 80, test.get('data'), test.get('fragment_size'), test.get('fragment_count'))
            except Exception as e:
                log.info(f"[ok] Ошибка: {repr(e)}")
            else:
                if result.split("\n")[0].find('200 ') != -1 and result.find(test['lookfor']) != -1:
                    log.warning("[f] Сайт открывается")
                    dpiresults.append(testname)
                elif result.split("\n")[0].find('200 ') == -1 and result.find(test['lookfor']) != -1:
                    log.warning("[!] Сайт не открывается, обнаружен пассивный DPI!")
                    dpiresults.append('Passive DPI')
                else:
                    log.info("[ok] Сайт не открывается")
    return list(set(dpiresults))

def test_dns():
    sites = dns_records_list
    sites_list = list(sites.keys())
    log.info("[O] Тестируем DNS")
    log.info("[O] Получаем эталонные DNS с сервера")
    try:
        remote_dns = urllib.request.urlopen("http://tac.rdp.ru/pub/getdns.php", timeout=10).read()
        remote_dns = sorted(_decode_bytes(remote_dns).split())
        log.info(f"\tЭталонные адреса:\t\t {str(remote_dns)}")
    except:
        remote_dns = None
        log.warning("[f] Не удалось получить DNS с сервера, результаты могут быть неточными")
    resolved_default_dns = _get_a_records(sites_list, timeout)
    if resolved_default_dns != 'False':
        log.info(f"\tАдреса через системные DNS:\t {str(resolved_default_dns)}")
    else:
        log.warning("\tНе удалось подключиться к системному DNS")
    resolved_google_dns = _get_a_records(sites_list, timeout, google_dns)
    if resolved_google_dns != 'False':
        log.info(f"\tАдреса через Google DNS:\t {str(resolved_google_dns)}")
    else:
        loggint.warning("\tНе удалось подключиться к Google DNS")

    if resolved_google_dns == 'False' or  resolved_default_dns == 'False':
        log.critical("Проблема с разрешением DNS на системном, либо google сервере")
        input("Нажмите Enter чтобы выйти...")
        exit(1)

    if (remote_dns):
        # Если получили IP с сервера, используем их
        dns_records = remote_dns
    else:
        dns_records = sorted([item for sublist in sites.values() for item in sublist])
    if resolved_default_dns == resolved_google_dns:
        if resolved_default_dns == dns_records:
            log.info("[ok] DNS-записи не подменяются")
            return 0
        else:
            log.warning("[f] DNS-записи подменяются")
            return 2
    log.warning("[?] Способ блокировки DNS определить не удалось")
    return 3



class WorkerThread(Thread):
  def __init__(self,url_list,url_list_lock,regexp,timeout,verbose):
    super(WorkerThread,self).__init__()
    self.kill_received=False
    self.url_list=url_list
    self.url_list_lock=url_list_lock
    self.regexp=regexp
    self.timeout=timeout
    self.verbose=verbose

  def stop(self):
    self._stop.set()

  def run(self):
    while not self.kill_received:
      nextproto, nexturl, needresolve = self.grab_next_url()
      if nexturl==None:break
      self.retrieve_url(nextproto,nexturl,needresolve)

  def grab_next_url(self):
    self.url_list_lock.acquire(1)
    if len(self.url_list)<1:
      nexturl=None
      nextproto=None
      needresolve=None
    else:
      nextproto, nexturl, needresolve = self.url_list[0]
      del self.url_list[0]
      percdone = float((total-len(url_list))*100/total)
      s = "Done: %1.2f%%"%percdone
      print("\b"*len(s)+s, end="")
      #print end="")
    self.url_list_lock.release()
    return [nextproto,nexturl,needresolve]


  def retrieve_url(self,nextproto,nexturl,needresolve):
    #print ("====%s %r==="%(nexturl,needresolve))
    if self.verbose:print ('################### %s - %s - %r #######################' % (nextproto,nexturl,needresolve))
    domain, port = getdomain(nexturl,nextproto)
    if needresolve:
        #ip = gethostbyname_or_timeout(domain, timeout_secs = 0.5)
        ip = _get_a_record(domain, self.timeout)
        if not ip or '0.0.0.0' in ip:
            return False
    if nextproto in ['http','https']:
        try:
            if os.path.isfile('cacert.pem'):
                page = requests.get(nexturl.replace("%20", " "),timeout=self.timeout,verify='cacert.pem').text
            else:
                page = requests.get(nexturl.replace("%20", " "),timeout=self.timeout).text
        except Exception as e:
            return
        if not re.findall(r'%s'%self.regexp,page):
            opend.append(nexturl)
            log.warning(f"\n[f] Открылся: {nexturl}")
    elif nextproto in ['newcamd525','mgcamd525']:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not sock.connect_ex((domain, int(port))):
            opend.append(nextproto+"://"+nexturl)
    else:
        print("Unknown proto: "+nextproto)
        return False

def domain2ip_url(url,ip,port,proto):
    return re.sub(r"(?<=^"+proto+":\/\/)[^\/]+",ip+":"+port,url)

def getproto(url):
    res=re.findall(r"^[^(:\/\/)]+",url)
    if not len(res):return False
    return res[0]

def getdomain(url, proto):
    res=re.findall(r"(?<="+proto+":\/\/)[^\/]+",url)
    if not len(res):return False
    if ':' in res[0]:
        return res[0].split(':')
    return [res[0], '80']


test_dns()
test_dpi()
input("Нажмите Enter чтобы продолжить...")

if f=='':
    if not os.path.isfile('dump.xml'):
        log.warning("Не могу найти dump.xml в этой директории")
        input("Нажмите Enter чтобы выйти...")
        exit(2)

else:
    if not os.path.isfile(f):
        log.warning(f"Can't find {f}")
        input("Нажмите Enter чтобы выйти...")
        exit(3)

opend=[]

url_list = []
type_ip_list = []

if f!='':
    f = open(f,'r')
    for line in f:
        url = line.strip()
        if not urlregex.match(url):
            log.warning(f'wrong url: {url}')
            input("Нажмите Enter чтобы выйти...")
            exit(4)
        proto = getproto(url)
        if not proto in ['http','https','newcamd525','mgcamd525']:
            log.warning(f"Ошибка определения протокола: {url}")
            input("Нажмите Enter чтобы выйти...")
            exit(5)
        urldomain, port = getdomain(url,proto)
        url_list.append([proto]+[url]+[True])
    f.close()
else:
    log.info("[ok] Начали разбирать dump.xml")
    dump = ET.parse('dump.xml')
    root = dump.getroot()
    for content in root:
        # if content.attrib['id']!=str(530007):
        #     continue
        subs_c = ips_c = domains = urls = urldomain = port = proto = founded_type_ip = None
        ips = []
        ips_c = content.findall('ip')
        subs_c = content.findall('ipSubnet')
        founded_type_ip = content.findall("[@blockType='ip']")
        #searching only type_ip tag
        if founded_type_ip:
            for content in founded_type_ip:
                ips_from_ipS = []
                ips_from_ip = []
                ipSubs = content.findall('ipSubnet')
                ips = content.findall('ip')
                for ipSub in ipSubs:
                    for ip in IPNetwork(ipSub.text):
                        ips_from_ipS.append(str(ip))
                for ip in ips:
                    for ip in IPNetwork(ip.text):
                        ips_from_ip.append(str(ip))
                # for ipSub in ipSubs:
                #     for i, ip in enumerate(IPNetwork(ipSub.text)):
                #         if i < 10:
                #             ips_from_ipS.append(str(ip))
                #         else:
                #             break
                # for ip in ips:
                #     for j, ip in enumerate(IPNetwork(ip.text)):
                #         if j < 10:
                #             ips_from_ip.append(str(ip))
                #         else:
                #             break
                if ips_from_ip:
                    type_ip_list.append(choice(ips_from_ip))
                    type_ip_list.append(choice(ips_from_ip))
                if ips_from_ipS:
                    type_ip_list.append(choice(ips_from_ipS))
                    type_ip_list.append(choice(ips_from_ipS))

        for ip in ips_c:
            ips.append(ip.text)
        try:
            blocktype = content.attrib['blockType']
        except KeyError:
            blocktype = "default"
 
        if blocktype != 'ip':
            for sub in subs_c:
                for ip in IPNetwork(sub.text):
                    ips.append(str(ip))

        domains = content.findall('domain')
        urls = content.findall('url')
        if urls:
            for url in urls:
                proto = getproto(url.text)
                urldomain, port = getdomain(url.text,proto)
                url_list.append([proto]+[url.text]+[True])
                if substitute:
                    for ip in ips:
                        url_list.append([proto]+[domain2ip_url(url.text, ip, port, proto)]+[False])
        else:
            if domains:
                for domain in domains:
                    url_list.append(['http',"http://" + domain.text]+[True])
                    url_list.append(['https',"https://" + domain.text]+[True])
            if substitute:
                for ip in ips:
                    url_list.append(['http',"http://" + str(ip)]+[False])
                    url_list.append(['https',"https://" + str(ip)]+[False])
total = len(url_list)

log.info("[O] Количество URL(type-ip) для проверки: " + str(len(type_ip_list)))
input("Нажмите Enter чтобы перейти к проверке...")
if not type_ip_list:
    print("Nothing to do")
    input("Нажмите Enter чтобы перейти к проверке url-filtering...\n")
else:
    from is_port_open import is_open, conn_threads, close_threads, statistics
    import is_port_open
    check_ip_thread_list = []
    try:
        for ip in type_ip_list:
            check_ip_thread = conn_threads(is_open, ip, 4)
            check_ip_thread_list.append(check_ip_thread)
            if int(len(check_ip_thread_list)) > int(n_ip_threads):
                map(close_threads, check_ip_thread_list) # в функцию close threads передаем элементы списка с помощью map
                log.debug('GC is Working!\n')
                check_ip_thread_list = []
                time.sleep(3) # helps to fix crash at windows
                #try make parallel gc and create new ones
    except KeyboardInterrupt:
        log.critical("\nCtrl-c! Остановка всех потоков...")
        exit(1)

log.info('TYPE IP CHECK FINISHED\n')
# log.info('Summary brief: ')
log.info('''Summary brief:
 {} \n
 {} \n
 {} \n
 {}
 '''.format(colored(f'[f] Opened ports {str(is_port_open.count_opened)}', 'red'),
            colored(f'[f] No rst received {str(is_port_open.count_no_rst)}', 'red'),
            colored(f'[f] Dst unreachable {str(is_port_open.count_dest_unreach)}', 'red'),
            colored(f'[ok] Closed ports {str(is_port_open.count_closed)}', 'green')
            ))
log.info('Details in type_ip_stat.txt')

try:
    with open('type_ip_stat.txt', 'w') as f:
        stats = '\n'.join(statistics)
        f.write(stats)
except OSError:
    with open('type_ip_stat.txt.new', 'w') as f:
            stats = '\n'.join(statistics)
            f.write(stats)

log.info("[O] Количество URL для проверки: " + str(total))
input("Нажмите Enter чтобы перейти к проверке...")
if total==0:
    log.critical("Nothing to do")
    input("Нажмите Enter чтобы выйти...")
    exit(0)


url_list_lock = Lock()
workerthreadlist=[]
for x in range(0,n_threads-1):
    newthread = WorkerThread(url_list,url_list_lock,regexp,timeout,verbose)
    workerthreadlist.append(newthread)
    newthread.start()

while len(workerthreadlist) > 0:
    try:
        workerthreadlist = [t.join(1) for t in workerthreadlist if t is not None and t.isAlive()]
    except KeyboardInterrupt:
        log.warning("\nCtrl-c! Остановка всех потоков...")
        for t in workerthreadlist:
            t.kill_received = True
        exit(0)

print()
perc = len(opend)*100/total
print(colored("[f]",'cyan'), end="") if perc else print(colored("[ok]",'cyan'),end="")
print (colored(f" Процент открывшихся сайтов: {str(perc)}%", 'cyan'))
if perc:
    log.warning("[f] Открывшиеся сайты:")
    for url in opend:
        log.warning(f"\t[f] {url}")
    input("Нажмите Enter чтобы выйти...")
