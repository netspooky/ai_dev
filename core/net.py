### Net Commands 
# All commands that have to do with networking / internet stuff 

import base64
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

async def wpRandom(room, event, cmdArgs):
    """
    !w - Get a random Wikipedia page
    """
    article = requests.get("https://en.wikipedia.org/wiki/Special:Random").url
    return article

async def secTrails(room, event, cmdArgs):
    """
    !dns - DNS Lookup with SecurityTrails API
    """
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
    """
    !ip - ipinfo IP Lookup
    """
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

async def bssid_lookup(room, event, cmdArgs):
    """
    !bssid - BSSID Lookup
    !bssid XX:XX:XX:XX:XX:XX
    """
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

async def getMACVendor(room, event, cmdArgs):
  """
  !mac - MAC Vendor Lookup Command
  """
  # TODO - Try a local lookup with ouisieee first, then do an API call if not found
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

async def headerGrab(room, event, cmdArgs):
    """
    !head - Header grabber
    """
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
    """
    Helper that resolves IP addresses
    """
    host_ip = socket.gethostbyname(host_name) 
    return host_ip

async def resolveHost(room, event, cmdArgs):
    """
    !host - Host Lookup Command
    """
    try:
        host_ip = await resolver(cmdArgs[0])
        return f"<pre><code>{host_ip}</code></pre>"
    except Exception as aiEx:
        await crashLog(event,aiEx)
        return f"<pre><code>Couldn't resolve IP!\n{aiEx}</code></pre>"

async def gn(ip):
    """
    Helper for the gn command
    """
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
    """
    !gn - Greynoise IP Lookup Command
    """
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
