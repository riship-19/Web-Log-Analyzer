import re
import pandas as pd

log_file = "sample_logs/access.log"

pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>.*?) HTTP/1.1" (?P<status>\d+) (?P<size>\d+) "-" "(?P<ua>.*?)"'
)

records=[]
with open(log_file) as f:
    for line in f:
        m=pattern.match(line)
        if m:
            records.append(m.groupdict())

df=pd.DataFrame(records)
print(df.head())

# detect attacks
df['attack']=False

df.loc[df['path'].str.contains("script",case=False),'attack']="XSS"
df.loc[df['path'].str.contains("OR '1'='1",case=False),'attack']="SQL Injection"
df.loc[df['path'].str.contains("../",case=False),'attack']="Directory Traversal"
df.loc[df['ua'].str.contains("sqlmap",case=False),'attack']="SQLmap Scanner"

print(df[df['attack']!=False])
