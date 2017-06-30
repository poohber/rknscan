#RKNScanner
Scanner for testing DPI + ability to scan Roskomnadzor registry and custom lists

##Requirements
```
pyOpenSSL 
ndg-httpsclient 
pyasn1 
dnspython3
colorama
termcolor

for dump download

suds-jurko
```

## Usage
```
Use only from Python version 3.6+
Usage: rknscan.py [options]

Options:
  -h, --help            show this help message and exit
  -r REGEXP, --regexp=REGEXP
                        Установить регулярное выражение, по которому будет
                        матчиться вывод открываемой страницы (тут необходимо
                        указать какой-либо кусок со страницы заглушки)
  -v, --verbose         Увеличить вербозность (для дебага)
  -n N_THREADS, --numthreads=N_THREADS
                        Установить количество потоков (defaul=500)
  -i N_IP_THREADS, --numipthreads=N_IP_THREADS
                        Установить количество потоков для проверки записей с block_type_ip (defaul=200)
                        Уменьшить, если появляется ошибка error.open.new_thread
  -t TIMEOUT, --timeout=TIMEOUT
                        Таймаут по истечению которого неответивший сайт
                        считается недоступным (default=3)
  -f FILE, --file=FILE  Указать файл с перечнем URL для проверки (НЕ в случае
                        реестра Роскомнадзора)
  -s, --substituteip    Добавление в выборку URL адресов, с
                        замененным доменом на IP адрес (в случае реестра
                        Роскомнадзора)
  -c, --console         Запуск в консольном режиме (без интерактива)

```

If we are going to check RKN registry - firstly we have to download it (dump.xml) manualy from http://vigruzki.rkn.gov.ru/tooperators_form/ and put it in the same directory with rknscan.py  
Also you can use file get_dump.py (use your own login/password)  
Usage get_dump:
```
python3.6 get_dump.py LOGIN PASSWORD
```

typically command to run rknscan.py:

```
python3.6 rknscan.py -t 5 -n 700 -c
```
