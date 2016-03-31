#RKNScanner
Scanner for testing DPI + ability to scan Roskomnadzor registry and custom lists

##Requirements
```
pyOpenSSL 
ndg-httpsclient 
pyasn1 
dnspython3
```

## Usage
```
Usage: rknscan.py [options]

Options:
  -h, --help            show this help message and exit
  -r REGEXP, --regexp=REGEXP
                        Установить регулярное выражение, по которому будет
                        матчиться вывод открываемой страницы (тут необходимо
                        указать какой-либо кусок со страницы заглушки)
  -v, --verbose         Увеличить вербозность (для дебага)
  -n N_THREADS, --numthreads=N_THREADS
                        Установить количество потоков (defaul=50)
  -t TIMEOUT, --timeout=TIMEOUT
                        Таймаут по истечению которого неответивший сайт
                        считается недоступным (default=3)
  -f FILE, --file=FILE  Указать файл с перечнем URL для проверки (НЕ в случае
                        реестра Роскомнадзора)
  -s, --substituteipnone
                        Запрет на добавление в выборку URL адресов, с
                        замененным доменом на IP адрес (в случае реестра
                        Роскомнадзора)

```

If we are going to check RKN registry - firstly we have to download it (dump.xml) manualy from http://vigruzki.rkn.gov.ru/tooperators_form/ and put it in the same directory with rknscan.py

typically command to run:

```
python3 rknscan.py -t 5 -n 700
```
