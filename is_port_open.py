#! /usr/bin/python3.6
# coding: utf-8
import socket
import random
import threading
import colorama
from termcolor import colored

statistics = []
count_opened = 0
count_closed = 0
count_no_rst = 0
count_dest_unreach = 0
def is_open(ip, end_range=4):
    global count_opened
    global count_closed
    global count_no_rst
    global count_dest_unreach
    # Генерируем список из рандомных портов
    ports = [random.randint(81, 5055) for x in range(end_range)]
    # ставим таймаут неответа на первый syn
    socket.setdefaulttimeout(2)
    opened_ports = []
    closed_ports = []
    no_rst = []
    dest_unreach = []
    for port in ports:
        try:
            conn = socket.socket()
            conn.connect((ip, port))
            conn.send(b'hello, world!')
            data = conn.recv(1024)
            conn.close()
            opened_ports.append(port)
            count_opened+=1
        except ConnectionRefusedError:
            conn.close()
            closed_ports.append(port)
            count_closed+=1
        except socket.timeout:
            conn.close()
            no_rst.append (port)
            count_no_rst+=1
        except OSError:
            dest_unreach.append(port)
            count_dest_unreach+=1
    if not len(opened_ports):
        opened_ports.append(0)
    if not closed_ports:
        closed_ports.append(0)
    if not len(no_rst):
        no_rst.append(0)

    statistics.append('{:*>60}'.format(''))
    statistics.append(f'Summary of {ip} check:\n')
    statistics.append(f'[f] Answered SYN {opened_ports}\n')
    statistics.append(f'[f] Dst unreachable {dest_unreach}\n')
    statistics.append(f'[f] Opened ports NO RST {no_rst}\n')
    statistics.append(f'[ok] Closed ports RST recieved {closed_ports}\n')
    statistics.append('{:*>60}'.format(''))
def conn_threads(function, ip, end_range=4):
    threads = []
    th = threading.Thread(target = function, args = (ip, end_range))
    th.start()
    threads.append(th)
    return threads

def close_threads(thread):
    for th in thread:
        th.join()
