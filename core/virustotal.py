import requests
import json

try:
    from core.helper import *
except ImportError:
    from helper import *

class VirusTotal:
    def __init__(self):
        self.api_key = SECRETS["keys"]["virus_total"]
        if len(self.api_key) == 0:
            return "[-] Please set up a Virus Total API key!"
        else:
            print("[+] Virus Total: API Key Loaded!")
    # !vt <hash>
    async def vt_search(self,room, event, cmdArgs):
        if self.api_key:
            vtHeaders = {'x-apikey': self.api_key}
            try:
              vtHash   = cmdArgs[0]
              vtOut    = ""
              url      = 'https://www.virustotal.com/api/v3/files/{}'.format(vtHash)
              res      = requests.get(url, headers=vtHeaders)
              data     = json.loads(res.text)
              vtd      = data['data']['attributes']
              aRes = data['data']['attributes']['last_analysis_results']
              vtOut += "--- File Meta ---\n"
              vtOut += f" VTID....: {data['data']['id']}\n"
              vtOut += f" Magic...: {vtd['magic']}\n"
              vtOut += f" MD5.....: {vtd['md5']}\n"
              vtOut += f" SHA1....: {vtd['sha1']}\n"
              vtOut += f" SHA256..: {vtd['sha256']}\n"
              vtOut += f" Type....: {vtd['type_description']}\n"
              vtOut += f" Tags....: {vtd['tags']}\n"
              if "exiftool" in vtd:
                vtOut += "\n--- Exif Data ---\n"
                vtExif = vtd['exiftool']
                for eK, eV in vtExif.items():
                    vtOut += f" {eK}: {eV}\n"
                vtOut += "\n--- Detections ---\n"
              for i in aRes:
                  eRes  = aRes[i]['result']
                  eName = aRes[i]['engine_name']
                  if eRes != None:
                      vtOut += f" {eName}: {eRes}\n"
                  else:
                      continue
              stats = data['data']['attributes']['last_analysis_stats']
              vtOut += "\n--- Stats ---\n"
              for s, v in stats.items():
                  vtOut += f" {s}: {v}\n"
              vtOut += f"\nLINK: {data['data']['links']['self']}"
              return f"<pre><code>{vtOut}</code></pre>"
            except Exception as aiEx:
              await crashLog(event,aiEx)
              return f"<pre><code>No Results or API Key Exhausted!\n{aiEx}</code></pre>"
        else:
            return "Please set up an API key to use this command."

VirusTotalCmd = VirusTotal()
