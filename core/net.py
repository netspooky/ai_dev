### Net Commands 
# All commands that have to do with networking / internet stuff 

from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
import base64
import shodan
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID
import textwrap
import re
import requests
import socket
import time
from greynoise.api import GreyNoise
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from core.helper import *
except ImportError:
    from helper import *

async def urlScanScan(room, event, cmdArgs):
    # Does an unlisted scan
    urlToScan = cmdArgs[0]
    urlScanAPIKey = SECRETS["keys"]["urlscan"]
    if len(urlScanAPIKey) == 0:
        return "Please configure a URL Scan API Key! https://urlscan.io"
    headers = {'API-Key':urlScanAPIKey,'Content-Type':'application/json'}
    pdata = {"url": urlToScan, "visibility": "unlisted"}
    scanResponse = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(pdata))
    scanResponseJson = json.loads(scanResponse.text)
    scanOut = ""
    scanOut += "<pre><code>"
    if 'success' in scanResponseJson['message']:
        scanResponseURL = scanResponseJson['result']
        scanOut += f"Full Scan Result URL: {scanResponseURL}\n"
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

async def urlScanSearch(room, event, cmdArgs):
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

async def wpRandom(room, event, cmdArgs):
    article = requests.get("https://en.wikipedia.org/wiki/Special:Random").url
    return article

async def secTrails(room, event, cmdArgs):
    domain     = cmdArgs[0]
    api_key    = SECRETS["keys"]["sectrails"]
    output_dir = SECRETS["config"]["output_dir"]
    fqdn       = SECRETS["config"]["domain"]
    if len(api_key) == 0:
        return "Please set up a Security Trails API key!"
    if domain[0:4] == "http":
      domain = domain.split("//")[1] # Quick n' Dirty
    try:
        url      = f"https://api.securitytrails.com/v1/domain/{domain}"
        headers  = {"Accept": "application/json", "apikey": api_key}
        response = requests.get(url, headers=headers)
        out      = response.json()
        ret      = "" # What is being returned
        ### Basic Stats
        ret += f"--- Stats for Host {out['hostname']} ---\n"
        if "a" in out["current_dns"]:
            ret += "\n[ A ]\n"
            for v in out["current_dns"]["a"]["values"]:
                ret += f"- {v['ip']} ({v['ip_organization']})\n"
        if "txt" in out["current_dns"]:
            ret += "\n[ TXT ]\n"
            for v in out["current_dns"]["txt"]["values"]:
                ret += f"- {v['value']}\n"
        if "ns" in out["current_dns"]:
            ret += "\n[ NS ]\n"
            for v in out["current_dns"]["ns"]["values"]:
                ret += f"- {v['nameserver']} ({v['nameserver_organization']})\n"
        if "mx" in out["current_dns"]:
            ret += "\n[ MX ]\n"
            for v in out["current_dns"]["mx"]["values"]:
                ret += f"- {v['hostname']} ({v['hostname_organization']})\n"
        ret += "\nSubdomain Count: {}\n".format(out["subdomain_count"])
        if out["subdomain_count"] > 0:
            url      = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers  = {"Accept": "application/json", "apikey": api_key}
            response = requests.get(url, headers=headers)
            out      = response.json()
            for s in out["subdomains"]:
              ret += f"\n- {s}"
        if len(ret) > 5000:
            fname = f"{output_dir}securitytrailz/{domain}.txt" # Add timestamp as well
            f = open(fname,'w')
            f.write(ret)
            f.close()
            return f"Your output was too big, I put it here: {fqdn}/securitytrailz/{domain}.txt"
        else:
            return f"<pre><code>{ret}</code></pre>"
    except:
      return "Something broke! (Probably the API key is exhausted)"

async def ipinfo(room, event, cmdArgs):
    ip  = cmdArgs[0]
    if len(ip) > 7:
        url = f"http://ipinfo.io/{ip}"
    else:
        return
    res = requests.get(url)
    data = json.loads(res.text)
    ipOut = ""
    keyList = ['hostname','city','region','country','loc','postal','phone','org']
    if 'error' in data:
        ipOut = 'Not a valid IP!'
        ip = await getFace('nay')
    elif valid_ip:
        ipOut = fmt1
        for k in keyList:
            if k in data:
                ipOut += f"{k}: {data[k]}\n"
        ipOut += fmt2
    else:
        ipOut = 'Not a valid IP!'
    return f"<h3>IP: {ip}</h3> {ipOut}"

#-> !bssid XX:XX:XX:XX:XX:XX
async def bssid_lookup(room, event, cmdArgs):
    if len(cmdArgs) == 0  or cmdArgs[0] == '-h':
        return "usage: !bssid <XX:XX:XX:XX:XX:XX>"
    else:
        if re.match(r'^([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])$', cmdArgs[0]):
            try:
                mac = urllib.parse.quote_plus(cmdArgs[0])
                api_key = SECRETS["keys"]["wigle"]
                if len(api_key) == 0:
                  return "Please set up a Wigle API key!"
                wigleLink = f"https://api.wigle.net/api/v2/network/search?onlymine=false&first=0&freenet=false&paynet=false&netid={mac}"
                headers = {'Authorization': 'Basic '+api_key}
                r = requests.get(wigleLink, headers=headers)
                data = r.json()
                #success check
                if data["success"] == False:
                    return "Something went wrong - Do you have a key?"
                elif data["totalResults"] == 0:
                    return "No data found"
                else:
                    dres = data["results"][0]
                    #generate google maps url
                    gmapsurl = f"https://www.google.com/maps/place/{dres['trilat']}+{dres['trilong']}"
                    cmdOut = "<h3>wigle.net BSSID Lookup</h3>"
                    cmdOut += f"Address: {dres['housenumber']} {dres['road']}, {dres['city']}, {dres['region']} {dres['country']}<br>"
                    cmdOut += f"Lat/Lon: {dres['trilat']}, {dres['trilong']}<br>"
                    cmdOut += f"Google Maps: {gmapsurl}<br>"
                    cmdOut += "<h3>Info</h3><pre><code>"
                    cmdOut += f"SSID: {dres['ssid']}\n"
                    cmdOut += f"NetID: {dres['netid']}\n"
                    cmdOut += f"Name: {dres['name']}\n"
                    cmdOut += f"Type: {dres['type']}\n"
                    cmdOut += f"Comment: '{dres['comment']}'\n"
                    cmdOut += f"WEP: {dres['wep']}\n"
                    cmdOut += f"Channel: {dres['channel']}\n"
                    cmdOut += f"Bcninterval: {dres['bcninterval']}\n"
                    cmdOut += f"Freenet: {dres['freenet']}\n"
                    cmdOut += f"DHCP: {dres['dhcp']}\n"
                    cmdOut += f"Paynet: {dres['paynet']}\n"
                    cmdOut += f"Users: {dres['userfound']}\n"
                    cmdOut += f"Encryption: {dres['encryption']}"
                    return cmdOut
            except Exception as aiEx:
                await crashLog(event,aiEx)
                return f"<pre><code>Error: {aiEx}</code></pre>"
        else:
            return "Not a valid BSSID!"

async def dnsdumpster2(room, event, cmdArgs):
    try:
      domain = cmdArgs[0]

      out = ''
      res = DNSDumpsterAPI(True).search(domain)

      out += "Domain:"
      out += res['domain']
      # DNS Servers
      out += "\n<h2>DNS Servers</h2><table><thead><tr><th>Domain</th><th>IP</th><th>AS</th><th>Provider</th><th>Country</th></tr></thead><tbody>"
      for entry in res['dns_records']['dns']:
          out += "<tr><td>{domain}</td><td>{ip}</td><td>{as}</td><td>{provider}</td><td>{country}</td></tr>".format(**entry)
      out += "</tbody></table>"

      out += "\n<h2>MX Records</h2><table><thead><tr><th>Domain</th><th>IP</th><th>AS</th><th>Provider</th><th>Country</th></tr></thead><tbody>"
      for entry in res['dns_records']['mx']:
          out += "<tr><td>{domain}</td><td>{ip}</td><td>{as}</td><td>{provider}</td><td>{country}</td></tr>".format(**entry)
      out += "</tbody></table>"
      out += "\n<h2>Host Records (A)</h2><table><thead><tr><th>Domain</th><th>rDNS</th><th>IP</th><th>AS</th><th>Provider</th><th>Country</th></tr></thead><tbody>"
      for entry in res['dns_records']['host']:
          if entry['reverse_dns']:
              out += "<tr><td>{domain}</td><td>{reverse_dns}</td><td>{ip}</td><td>{as}</td><td>{provider}</td><td>{country}</td></tr>".format(**entry)
          else:
              out += "<tr><td>{domain}</td><td>-</td><td>{ip}</td><td>{as}</td><td>{provider}</td><td>{country}</td></tr>".format(**entry)
      out += "</tbody></table>"
      out += "\n<h2>TXT Records</h2><ul>"
      for entry in res['dns_records']['txt']:
          out += f"<li>{entry}</li>"
      out += "</ul>"
    except:
        out = "No results!"
    return out

async def dnsdumpster(room, event, cmdArgs):
    try:
      domain = cmdArgs[0]

      final_result = ''
      res = DNSDumpsterAPI(True).search(domain)

      final_result += "####### Domain #######\n"
      final_result += res['domain']
      final_result += "\n####### DNS Servers #######\n"
      for entry in res['dns_records']['dns']:
          final_result += "{domain} ({ip}) {as} {provider} {country}\n".format(**entry)
      final_result += "\n####### MX Records #######\n"
      for entry in res['dns_records']['mx']:
          final_result += "{domain} ({ip}) {as} {provider} {country}\n".format(**entry)
      final_result += "\n####### Host Records (A) #######\n"
      for entry in res['dns_records']['host']:
          if entry['reverse_dns']:
              final_result += "{domain} ({reverse_dns}) ({ip}) {as} {provider} {country}\n".format(**entry)
          else:
              final_result += "{domain} ({ip}) {as} {provider} {country}\n".format(**entry)
      final_result += "\n####### TXT Records #######\n"
      for entry in res['dns_records']['txt']:
          final_result += entry + "\n" 
    except:
        final_result = "No results!"
    return "<pre><code>" + final_result + "</code></pre>"
    ### Fix when you figure out images
    #try:
    #    content_type = "image/png"
    #    content = base64.b64decode(res['image_data'])
    #    imgurl = bot.client.upload(content,content_type)
    #    room.send_text("DNS Map:")
    #    room.send_file(imgurl,'map.png')
    #except Exception as aiEx:
    #    await crashLog(event,aiEx)

async def bgpViewASN(room, event, cmdArgs):
  rlSleep = 0.5 # Ratelimit...
  try:
    asn = cmdArgs[0]
    bgpOut = ""
    url = f"https://api.bgpview.io/asn/{asn}"
    url_prefixes = url + "/prefixes"
    url_peers = url + "/peers"
    url_upstreams = url + "/upstreams"
    url_downstreams = url + "/downstreams"
    url_ixs = url + "/ixs"
    res = requests.get(url)
    data = json.loads(res.text)
    if data["status"] == "ok":
      asnd = data['data']
      bgpOut += "[ ASN Data ]\n"
      bgpOut += f"Name...: {asnd['name']}\n"
      bgpOut += f"Desc...: {asnd['description_short']}\n"
      bgpOut += f"Country: {asnd['country_code']}\n"
      bgpOut += f"Website: {asnd['website']}\n"
      bgpOut += f"Contact: {asnd['email_contacts'][0]}\n"
      bgpOut += f"Abuse..: {asnd['abuse_contacts'][0]}\n"
      bgpOut += f"Address: {' '.join(asnd['owner_address'])}\n"
    time.sleep(rlSleep)
    bgpOut += "\n[ Prefixes ]\n"
    res = requests.get(url_prefixes)
    data = json.loads(res.text)
    for prefix in data["data"]["ipv4_prefixes"]:
      bgpOut += f"  {prefix['prefix']} | {prefix['name']} | {prefix['description']}\n"
    ### Get Peers
    time.sleep(rlSleep)
    bgpOut += "\n[ Peers ]\n"
    res = requests.get(url_peers)
    data = json.loads(res.text)
    for peers in data["data"]["ipv4_peers"]:
      bgpOut += f"  AS{peers['asn']} | {peers['name']} | {peers['description']} | {peers['country_code']}\n"
    ### Upstreams
    time.sleep(rlSleep)
    bgpOut += "\n[ Upstreams ]\n"
    res = requests.get(url_upstreams)
    data = json.loads(res.text)
    for ups in data["data"]["ipv4_upstreams"]:
      bgpOut += f"  AS{ups['asn']} | {ups['name']} | {ups['description']} | {ups['country_code']}\n"
      bgpOut += f"  Graph: {data['data']['combined_graph']}\n"
    ### Downstreams
    time.sleep(rlSleep)
    bgpOut += "\n[ Downstreams ]\n"
    res = requests.get(url_downstreams)
    data = json.loads(res.text)
    for ds in data["data"]["ipv4_downstreams"]:
      bgpOut += f"  AS{ds['asn']} | {ds['name']} | {ds['description']} | {ds['country_code']}\n"
    ### IXs
    time.sleep(rlSleep)
    bgpOut += "\n[ IXs ]\n"
    res = requests.get(url_ixs)
    data = json.loads(res.text)
    for ixs in data["data"]:
      bgpOut += f"    IX ID: {ixs['ix_id']}\n"
      bgpOut += f"     Name: {ixs['name']}\n"
      bgpOut += f"Full Name: {ixs['name_full']}\n"
      bgpOut += f"  Country: {ixs['country_code']}\n"
      bgpOut += f"     City: {ixs['city']}\n"
      bgpOut += f"     IPv4: {ixs['ipv4_address']}\n"
      bgpOut += f"     IPv6: {ixs['ipv6_address']}\n"
      bgpOut += f"    Speed: {ixs['speed']}\n\n"
    return f"<pre><code>{bgpOut}</code></pre>"
  except Exception as aiEx:
    await crashLog(event,aiEx)
    return f"<pre><code>Error: {aiEx}</code></pre>"

async def bgpViewPrefix(room, event, cmdArgs):
  prefix = cmdArgs[0]
  try:
    bgpOut = ""
    url = f"https://api.bgpview.io/prefix/{prefix}"
    res = requests.get(url)
    data = json.loads(res.text)
    if data["status"] == "ok":
        bgpOut += "[ Prefix Info ]\n\n"
        bgpOut += f" PREFIX...: {data['data']['prefix']}\n"
        bgpOut += f" NAME.....: {data['data']['name']}\n"
        bgpOut += f" DESC.....: {data['data']['description_short']}\n"
        bgpOut += f" ADDRESS..: {' '.join(data['data']['owner_address'])}\n" # Confirm this one
        bgpOut += f" ALLOCATED: {data['data']['rir_allocation']['date_allocated']}\n"
        bgpOut += "\n[ ASNs ]\n\n"
        for i in data["data"]["asns"]:
            bgpOut += f" ASN......: AS{i['asn']}\n"
            bgpOut += f" Name.....: {i['name']}\n"
            bgpOut += f" Desc.....: {i['description']}\n"
            bgpOut += f" Country..: {i['country_code']}\n"
            bgpOut += " Upstreams:\n"
            for u in i["prefix_upstreams"]:
                bgpOut += f"   AS{u['asn']} | {u['name']} | {u['description']} | {u['country_code']}\n"
    return "<pre><code>"+bgpOut+"</code></pre>"
  except Exception as aiEx:
    await crashLog(event,aiEx)
    return f"<pre><code>Error: {aiEx}</code></pre>"

async def getMACVendor(room, event, cmdArgs):
  # Try a local lookup with ouisieee first, then do an API call if not found
  try:
    mac = cmdArgs[0]
    url = f"https://api.macvendors.com/{mac}"
    res = requests.get(url)
    data = res.text
    if len(data) > 0:
      return f"Vendor: {data}"
    else:
      return "No data!"
  except Exception as aiEx:
    await crashLog(event,aiEx)
    return f"<pre><code>Error: {aiEx}</code></pre>"

async def shodanGetIP(banner):
    if 'ipv6' in banner:
        return banner['ipv6']
    return banner['ip_str']

async def shodanSearch(room, event, cmdArgs):
  # Show the host information in a user-friendly way and try to include
  # as much relevant information as possible.
  try:
    search_term = cmdArgs[0]
    SHODAN_API_KEY = SECRETS["keys"]["shodan"]
    if len(SHODAN_API_KEY) == 0:
      return "Please set up a Shodan API key!"
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
      host = api.host(search_term)
    except:
      return "<pre><code>No results!</code></pre>"
    output  = """"""
    output += await shodanGetIP(host) + '\n'
    if len(host['hostnames']) > 0:
        output += u'{:25s}{}\n'.format('Hostnames:', ';'.join(host['hostnames']))

    if 'city' in host and host['city']:
        output += u'{:25s}{}\n'.format('City:', host['city'])

    if 'country_name' in host and host['country_name']:
        output += u'{:25s}{}\n'.format('Country:', host['country_name'])

    if 'os' in host and host['os']:
        output += u'{:25s}{}\n'.format('Operating System:', host['os'])

    if 'org' in host and host['org']:
        output += u'{:25s}{}\n'.format('Organization:', host['org'])

    if 'last_update' in host and host['last_update']:
        output += '{:25s}{}\n'.format('Updated:', host['last_update'])

    output += '{:25s}{}\n\n'.format('Number of open ports:', len(host['ports']))

    # Output the vulnerabilities the host has
    if 'vulns' in host and len(host['vulns']) > 0:
        vulns = []
        for vuln in host['vulns']:
            if vuln.startswith('!'):
                continue
            if vuln.upper() == 'CVE-2014-0160':
                vulns.append('Heartbleed')
            else:
                vulns.append(vuln)

        if len(vulns) > 0:
            output += '{:25s}'.format('Vulnerabilities:')

            for vuln in vulns:
                output += vuln + '\t'

            output += ''

    output += ''

    # If the user doesn't have access to SSL/ Telnet results then we need
    # to pad the host['data'] property with empty banners so they still see
    # the port listed as open. (#63)
    if len(host['ports']) != len(host['data']):
        # Find the ports the user can't see the data for
        ports = host['ports']
        for banner in host['data']:
            if banner['port'] in ports:
                ports.remove(banner['port'])

        # Add the placeholder banners
        for port in ports:
            banner = {
                'port': port,
                'transport': 'tcp',  # All the filtered services use TCP
                'timestamp': host['data'][-1]['timestamp'],  # Use the timestamp of the oldest banner
                'placeholder': True,  # Don't store this banner when the file is saved
            }
            host['data'].append(banner)

    output += 'Ports:\n'
    for banner in sorted(host['data'], key=lambda k: k['port']):
        product = ''
        version = ''
        if 'product' in banner and banner['product']:
            product = banner['product']
        if 'version' in banner and banner['version']:
            version = '({})'.format(banner['version'])

        output += '{:>7d}'.format(banner['port'])
        if 'transport' in banner:
            output += '/'
            output += '{} '.format(banner['transport'])
        output += '{} {}\n'.format(product, version)

        #if history:
            # Format the timestamp to only show the year-month-day
        #    date = banner['timestamp'][:10]
        #    output += '\t\t({})'.format(date)
        output += ''

        if 'ssl' not in banner and banner['data']:
            tmp = banner['data']
            output += '{}\n'.format(textwrap.indent(banner['data'], '\t'))

        # Show optional ssl info
        if 'ssl' in banner:
            if 'versions' in banner['ssl'] and banner['ssl']['versions']:
                output += '\t|-- SSL Versions: {}\n'.format(', '.join([item for item in sorted(banner['ssl']['versions']) if not version.startswith('-')]))
            if 'subject' in banner['ssl']['cert']:
                output += '\t|-- Subject: {}\n'.format(', '.join("{}={}".format(key,value) for key,value in banner['ssl']['cert']['subject'].items()))
            if 'dhparams' in banner['ssl'] and banner['ssl']['dhparams']:
                output += '\t|-- Diffie-Hellman Parameters:\n'
                output += '\t\t{:15s}{}\n\t\t{:15s}{}\n'.format('Bits:', banner['ssl']['dhparams']['bits'], 'Generator:', banner['ssl']['dhparams']['generator'])
                if 'fingerprint' in banner['ssl']['dhparams']:
                    output += '\t\t{:15s}{}\n'.format('Fingerprint:', banner['ssl']['dhparams']['fingerprint'])
            if 'subjectAltName' in str(banner['ssl']['cert']['extensions']):
                 cert = x509.load_pem_x509_certificate(banner['ssl']['chain'][0].encode('utf-8'), default_backend())
                 ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                 output += '\t|-- Subject alt names: {}\n'.format(', '.join([str(item.value) for item in ext.value]))

    output = re.sub(r"\x00|\x01|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0b|\x0c|\x0e|\x0f|\x10|\x11|\x12|\x13|\x14|\x15|\x16|\x17|\x18|\x19|\x1a|\x1b|\x1c|\x1d|\x1e|\x7f", lambda m: "\\" + hex(bytearray(m.group(0).encode("utf-8"))[0]) if m.group(0) else '0',output)
    return "<pre><code>"+output+"</code></pre>"
  except Exception as aiEx:
    await crashLog(event,aiEx)
    return f"<pre><code>Error: {aiEx}</code></pre>"

async def headerGrab(room, event, cmdArgs):
  try:
    url = cmdArgs[0]
    if url[0:4] != "http":
      url = "http://" + url
    rUA = await getLine("assets/useragents.txt") # Random User Agent
    rUA = rUA.split("\n")[0]
    headers = { 'User-Agent': rUA }
    r = requests.get(url, headers=headers, timeout=15, verify=False)
    h = r.headers
    headerOut = ""
    headerOut += f"URL: {url}\n"
    headerOut += f" UA: {rUA}\n"
    headerOut += "--------------------\n"
    headerOut += f" Status: {r.status_code}\n"
    if r.is_redirect:
        headerOut += " Redirect: True\n"
    for hK, hV in h.items():
        headerOut += f" {hK}: {hV}\n"
    headerOut += f" Content-Length: {len(r.text)}"
    return "<pre><code>"+headerOut+"</code></pre>"

  except Exception as aiEx:
    await crashLog(event,aiEx)
    return f"<pre><code>Error: {aiEx}</code></pre>"

async def resolver(host_name):
  host_ip = socket.gethostbyname(host_name) 
  return host_ip

async def resolveHost(room, event, cmdArgs):
  try:
    host_ip = await resolver(cmdArgs[0])
    return f"<pre><code>{host_ip}</code></pre>"
  except Exception as aiEx:
    await crashLog(event,aiEx)
    return f"<pre><code>Couldn't resolve IP!\n{aiEx}</code></pre>"

async def gn(ip):
  gnapi = GreyNoise()
  noise = gnapi.ip(ip)
  gnOut = ""
  if 'seen' in noise:
    gnOut += f"IP: {ip}\n"
    gnOut += f"Seen: {noise['seen']}\n"
    if 'classification' in noise:
      gnc = noise['classification']
      gnOut += f"Classification: {gnc}\n"
      if 'tags' in noise:
        gnOut += "Tags:\n"
        for tag in noise['tags']:
          gnOut += f"- {tag}\n"
    else:
      return gnOut
  else:
    gnOut = "No results :("
  return gnOut

async def gnWrapper(room, event, cmdArgs):
  try:
    searchIP = cmdArgs[0]
    if await valid_ip(searchIP):
      ip = searchIP
    else:
      ip = await resolver(searchIP)
    gnR = await gn(ip)
    if gnR:
      return f"<pre><code>{gnR}</code></pre>"
  except Exception as aiEx:
    await crashLog(event,aiEx)
    return f"<pre><code>{aiEx}</code></pre>"
