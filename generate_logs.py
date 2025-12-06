import random
from datetime import datetime, timedelta
import os

os.makedirs("sample_logs", exist_ok=True)

ips = ["127.0.0.1","192.168.1.12","10.0.0.5","203.0.113.7","198.51.100.23"]
paths = ["/index.html","/login.php","/products?id=1","/search?q=test",
         "/../../../etc/passwd","/search?q=<script>alert(1)</script>",
         "/products?id=1' OR '1'='1"]
methods=["GET","POST"]
status_codes=[200,404,401,403]
agents=["Mozilla/5.0","curl/7.68.0","sqlmap/1.4","Wget/1.20"]

base_time=datetime.now()

with open("sample_logs/access.log","w") as f:
    for i in range(200):
        ip=random.choice(ips)
        path=random.choice(paths)
        method=random.choice(methods)
        status=random.choice(status_codes)
        ua=random.choice(agents)
        t=base_time+timedelta(seconds=i)
        line=f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} 123 "-" "{ua}"\n'
        f.write(line)

print("Log file created at sample_logs/access.log")
