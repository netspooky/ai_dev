import requests
import json
import time

try:
    from core.helper import *
except ImportError:
    from helper import *

class UrlScan:
    def __init__(self):
        self.api_key = SECRETS["keys"]["urlscan"]
        if len(self.api_key) == 0:
            return "Please configure a URL Scan API Key! https://urlscan.io"
        else:
            print("[+] UrlScan: API Key Loaded!")
    async def us_scan(self, room, event, cmdArgs):
        """
        !urlscan - Perform an unlisted scan using urlscan
        """
        urlToScan = cmdArgs[0]
        headers = {'API-Key':self.api_key,'Content-Type':'application/json'}
        pdata = {"url": urlToScan, "visibility": "unlisted"}
        scanResponse = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(pdata))
        scanResponseJson = json.loads(scanResponse.text)
        scanOut = ""
        if 'success' in scanResponseJson['message']:
            scanResponseURL = scanResponseJson['result']
            scanOut += f"Full Scan Result URL: {scanResponseURL}\n"
            scanOut += "<pre><code>"
            # It takes a bit of time to get the full results from the scan available to the API, need to wait or send something to dispatch to grab it later.
            scanResponseAPIURL = scanResponseJson['api']
            try:
                for reqTry in range(0,15):
                    scanResultResponse = requests.get(scanResponseAPIURL)
                    if scanResultResponse.status_code == 200:
                        scanResultJson = json.loads(scanResultResponse.text)
                        scanOut += "[[ Requests ]]\n"
                        lastDocUrl = ""
                        for jReq in scanResultJson['data']['requests']:
                            respStatus = "???"
                            if jReq['request']['documentURL'] != lastDocUrl:
                                lastDocUrl = jReq['request']['documentURL']
                                scanOut += f"{jReq['request']['documentURL']}\n"
                            if 'response' in jReq['response']:
                                respStatus = jReq['response']['response']['status']
                            scanOut += f"  -> [{respStatus}] {jReq['request']['request']['method']} {jReq['request']['request']['url']}\n"
                        if 'links' in scanResultJson['data']:
                            scanOut += "\n[[ Links ]]\n"
                            for dlink in scanResultJson['data']['links']:
                                scanOut += f"- {dlink['href']} {dlink['text']}\n"
                        if 'console' in scanResultJson['data']:
                            scanOut += "\n[[ Console ]]\n"
                            for consoleMsg in scanResultJson['data']['console']:
                                scanOut += f"{consoleMsg['message']['url']} [{consoleMsg['message']['source']} {consoleMsg['message']['level']}] {consoleMsg['message']['text']}"
                        scanOut += "</code></pre>"
                        break
                    else:
                         print(f"{scanResultResponse} - sleeping {reqTry}")
                         time.sleep(1)
            except Exception as aiEx:
                await crashLog(event,aiEx)
                return f"<pre><code>Error: {aiEx}</code></pre>"
            return scanOut
        else:
            scanOut += "<pre><code>"
            scanOut += scanResponseJson['message']
            scanOut += "</code></pre>"
            return scanOut
    
    async def us_search(self, room, event, cmdArgs):
        """
        !uss - Search for a domain via urlscan
        """
        domain    = cmdArgs[0]
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        try:
            req = requests.get(url)
            data = json.loads(req.text)
            out = ""
            results = data["results"]
            resnum = 0
            out += f"{len(results)} results!\n"
            for r in results:
                resnum = resnum + 1
                out += f"Result {resnum} <pre><code>"
                out += f"URL: {r['task']['url']}\n"
                out += f"Domain: {r['task']['domain']}\n"
                out += f"Time: {r['task']['time']}\n"
                out += f"UUID: {r['task']['uuid']}\n"
                out += "Stats --------\n"
                out += f"Unique IPs: {r['stats']['uniqIPs']}\n"
                out += f"Unique Countries: {r['stats']['uniqCountries']}\n"
                out += f"Data Length: {r['stats']['dataLength']}\n"
                out += f"Encoded Data Length: {r['stats']['encodedDataLength']}\n"
                out += f"Requests: {r['stats']['requests']}\n"
                out += "Page --------\n"
                if 'title' in r['page']:
                    out += f"Title: {r['page']['title']}\n"
                if 'url' in r['page']:
                    out += f"URL: {r['page']['url']}\n"
                if 'status' in r['page']:
                    out += f"Status: {r['page']['status']}\n"
                if 'ip' in r['page']:
                    out += f"IP: {r['page']['ip']}\n"
                if 'ptr' in r['page']:
                    out += f"ptr: {r['page']['ptr']}\n"
                if 'server' in r['page']:
                    out += f"Server Type: {r['page']['server']}\n"
                if 'redirected' in r['page']:
                    out += f"Redirect: {r['page']['redirected']}\n"
                if 'mimeType' in r['page']:
                    out += f"MIME Type: {r['page']['mimeType']}\n"
                if 'country' in r['page']:
                    out += f"Country: {r['page']['country']}\n"
                if 'tlsValidFrom' in r['page']:
                    out += f"TLS Valid From: {r['page']['tlsValidFrom']}\n"
                if 'tlsValidDays' in r['page']:
                    out += f"TLS Valid Days: {r['page']['tlsValidDays']}\n"
                if 'tlsAgeDays' in r['page']:
                    out += f"TLS Age Days: {r['page']['tlsAgeDays']}\n"
                if 'tlsIssuer' in r['page']:
                    out += f"TLS Issuer: {r['page']['tlsIssuer']}\n"
                if 'asn' in r['page']:
                    out += f"ASN: {r['page']['asn']}\n"
                if 'asnname' in r['page']:
                    out += f"ASN Name: {r['page']['asnname']}\n"
                out += "Links --------\n"
                out += f"URL Scan Link: {r['result']}\n"
                out += f"Page Screenshot: {r['screenshot']}\n"
                out += "</code></pre>"
            return out
        except Exception as aiEx:
          await crashLog(event,aiEx)
          return f"<pre><code>Error: {aiEx}</code></pre>"

UrlScanCmd = UrlScan()
