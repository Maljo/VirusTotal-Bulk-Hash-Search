#install the following libraries..
#pip install virustotal-api
#pip install numpy==1.19.3
#pip install pandas
#Place the script and list of hashes(.txt) in the same directory and run:
# vtcsv.py hashes.txt

import pandas as pd
import json
import argparse
import sys
import time
from virus_total_apis import PublicApi as VirusTotalPublicApi

url = 'https://www.virustotal.com/vtapi/v2/file/report'

p = argparse.ArgumentParser()
p.add_argument('file', type=str, help='list of hashes')
args = p.parse_args()

API_KEY = '(******API_KEY******'
virustotal = VirusTotalPublicApi(API_KEY)

f = open(sys.argv[1])
l = f.readlines()
	
all_data = []

for line in l:
    response = virustotal.get_file_report(line)
    json_data = json.loads(json.dumps(response))
    r = json_data['results']

    if r:
        all_data.append(r)
    print(all_data)

    df = pd.DataFrame.from_records(all_data)
    df.to_csv('vt_search.csv', index=False)
    time.sleep(20)
f.close()
