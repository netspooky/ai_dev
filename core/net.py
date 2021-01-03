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
from greynoise.api import GreyNoise
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from core.helper import *
except ImportError:
    from helper import *

async def secTrails(room,event):
    await aiLog(event)
    args = event.body.split()
    domain = args[1]
    api_key = SECRETS["keys"]["sectrails"]
    output_dir = SECRETS["config"]["output_dir"]
    fqdn = SECRETS["config"]["domain"]
    if len(api_key) == 0:
        return "Please set up a Security Trails API key!"
    if domain[0:4] == "http":
      domain = domain.split("//")[1] # Quick n' Dirty
    try:
        url      = "https://api.securitytrails.com/v1/domain/{}".format(domain)
        headers  = {"Accept": "application/json", "apikey": api_key}
        response = requests.get(url, headers=headers)
        out      = response.json()
        ret      = "" # What is being returned
        ### Basic Stats
        ret += "--- Stats for Host {} ---\n".format(out["hostname"])
        if "a" in out["current_dns"]:
            ret += "\n[ A ]\n"
            for v in out["current_dns"]["a"]["values"]:
                ret += "- {} ({})\n".format(v["ip"],v["ip_organization"])
        if "txt" in out["current_dns"]:
            ret += "\n[ TXT ]\n"
            for v in out["current_dns"]["txt"]["values"]:
                ret += "- {}\n".format(v["value"])
        if "ns" in out["current_dns"]:
            ret += "\n[ NS ]\n"
            for v in out["current_dns"]["ns"]["values"]:
                ret += "- {} ({})\n".format(v["nameserver"],v["nameserver_organization"])
        if "mx" in out["current_dns"]:
            ret += "\n[ MX ]\n"
            for v in out["current_dns"]["mx"]["values"]:
                ret += "- {} ({})\n".format(v["hostname"],v["hostname_organization"])
        ret += "\nSubdomain Count: {}\n".format(out["subdomain_count"])
        if out["subdomain_count"] > 0:
            url      = "https://api.securitytrails.com/v1/domain/{}/subdomains".format(domain)
            headers  = {"Accept": "application/json", "apikey": api_key}
            response = requests.get(url, headers=headers)
            out      = response.json()
            for s in out["subdomains"]:
              ret += "\n- {}".format(s)
        if len(ret) > 5000:
            fname = output_dir+'securitytrailz/'+domain+".txt" # Add timestamp as well
            f = open(fname,'w')
            f.write(ret)
            f.close()
            return "Your output was too big, I put it here: " + fqdn + "/securitytrailz/"+domain+".txt"
        else:
            return "<pre><code>"+ret+"</code></pre>"
    except:
      return "Something broke! (Probably the API key is exhausted)"

async def ipinfo(room, event):
    await aiLog(event)
    args = event.body.split()
    ip  = args[1]
    if len(ip) > 5:
        url = 'http://ipinfo.io/{}'.format(ip)
    else:
        return
    res = requests.get(url)
    data = json.loads(res.text)
    #print(data)
    ipOut = ''
    keyList = ['hostname','city','region','country','loc','postal','phone','org']
    if 'error' in data:
        ipOut = 'Not a valid IP!'
        ip = await getFace('nay')
    elif await valid_ip:
        ipOut = fmt1
        for k in keyList:
            if k in data:
                ipOut += '{}: {}\n'.format(k,data[k])
        ipOut += fmt2
    else:
        ipOut = 'Not a valid IP!'
    return '<h3>IP: {}</h3> {}'.format(ip,ipOut)

#-> !bssid XX:XX:XX:XX:XX:XX
async def bssid_lookup(room, event):
    await aiLog(event)
    args = event.body.split()
    if len(args) <= 1 or args[1] == '-h':
        return "usage: !bssid <XX:XX:XX:XX:XX:XX>"
    else:
        if re.match(r'^([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])$', args[1]):
            try:
                mac = urllib.parse.quote_plus(args[1])
                api_key = SECRETS["keys"]["wigle"]
                if len(api_key) == 0:
                  return "Please set up a Wigle API key!"
                wigleLink = "https://api.wigle.net/api/v2/network/search?onlymine=false&first=0&freenet=false&paynet=false&netid={}".format(mac)
                headers = {'Authorization': 'Basic '+api_key}
                r = requests.get(wigleLink, headers=headers)
                data = r.json()
                
                #success check
                if data["success"] == False:
                    return "Something went wrong - Do you have a key?"
                
                elif data["totalResults"] == 0:
                    return "No data found"
                
                else:
                    trilat      = data["results"][0]["trilat"]
                    trilong     = data["results"][0]["trilong"]
                    ssid        = data["results"][0]["ssid"]
                    housenumber = data["results"][0]["housenumber"]
                    road        = data["results"][0]["road"]
                    city        = data["results"][0]["city"]
                    region      = data["results"][0]["region"]
                    country     = data["results"][0]["country"]
                    netid       = data["results"][0]["netid"]
                    name        = data["results"][0]["name"]
                    typeofnet   = data["results"][0]["type"]
                    comment     = data["results"][0]["comment"]
                    wep         = data["results"][0]["wep"]
                    channel     = data["results"][0]["channel"]
                    bcninterval = data["results"][0]["bcninterval"]
                    freenet     = data["results"][0]["freenet"]
                    dhcp        = data["results"][0]["dhcp"]
                    paynet      = data["results"][0]["paynet"]
                    userFound   = data["results"][0]["userfound"]
                    encryption  = data["results"][0]["encryption"]
                    
                    #generate google maps url
                    gmapsurl = "https://www.google.com/maps/place/{}+{}".format(trilat, trilong)
                    
                    #print results
                    return '''<pre><code>
-------------------------------
Approximate location:\n
Latitude: {}
Longtitude: {}\n
Housenumber: {}
Road: {}
City: {}
Region: {}
Country: {}
-------------------------------
Info:<br>
SSID: {}
NetID: {}
Name: {}
Type: {}
Comment: "{}"
WEP: {}
Channel: {}
Bcninterval: {}
Freenet: {}
DHCP: {}
Paynet: {}
Users: {}
Encryption: {}
-------------------------------
Google Maps: {}
-------------------------------
                    </code></pre>'''.format(trilat, trilong, housenumber, road, city, region, country, ssid, netid, name, typeofnet, comment, wep, channel, bcninterval, freenet, dhcp, paynet, userFound, encryption, gmapsurl)
            except Exception as aiEx:
                await crashLog(event,aiEx)
        else:
            return "Nice Try"

async def dnsdumpster(room, event):
    try:
      await aiLog(event)
      args = event.body.split()
      domain = args[1]

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

async def bgpViewASN(room,event):
  await aiLog(event)
  args = event.body.split()
  try:
    asn = args[1]
    bgpOut = ""
    url = 'https://api.bgpview.io/asn/{}'.format(asn)
    res = requests.get(url)
    data = json.loads(res.text)
    if data["status"] == "ok":
      bgpOut += "[ ASN Data ]\n"
      asn_name = data["data"]["name"]
      asn_desc = data["data"]["description_short"]
      asn_country = data["data"]["country_code"]
      asn_webs = data["data"]["website"]
      asn_email = data["data"]["email_contacts"][0]
      asn_abuse = data["data"]["abuse_contacts"][0]
      asn_addr = data["data"]["owner_address"]
      bgpOut += "Name...: {}\n".format(asn_name)
      bgpOut += "Desc...: {}\n".format(asn_desc)
      bgpOut += "Country: {}\n".format(asn_country)
      bgpOut += "Website: {}\n".format(asn_webs)
      bgpOut += "Contact: {}\n".format(asn_email)
      bgpOut += "Abuse..: {}\n".format(asn_abuse)
      bgpOut += "Address: "+" ".join(asn_addr) + "\n"
    bgpOut += "\n[ Prefixes ]\n"
    url = 'https://api.bgpview.io/asn/{}/prefixes'.format(asn)
    res = requests.get(url)
    data = json.loads(res.text)
    for i in data["data"]["ipv4_prefixes"]:
      bgpOut += "  {} | {} | {}\n".format(i["prefix"],i["name"],i["description"])
    ### Get Peers
    bgpOut += "\n[ Peers ]\n"
    url = 'https://api.bgpview.io/asn/{}/peers'.format(asn)
    res = requests.get(url)
    data = json.loads(res.text)
    for i in data["data"]["ipv4_peers"]:
      bgpOut += "  AS{} | {} | {} | {}\n".format(i["asn"],i["name"],i["description"],i["country_code"])
    ### Upstreams
    bgpOut += "\n[ Upstreams ]\n"
    url = 'https://api.bgpview.io/asn/{}/upstreams'.format(asn)
    res = requests.get(url)
    data = json.loads(res.text)
    for i in data["data"]["ipv4_upstreams"]:
      bgpOut += "  AS{} | {} | {} | {}\n".format(i["asn"],i["name"],i["description"],i["country_code"])
      bgpOut += "  Graph: {}\n".format(data["data"]["combined_graph"])
    ### Downstreams
    bgpOut += "\n[ Downstreams ]\n"
    url = 'https://api.bgpview.io/asn/{}/downstreams'.format(asn)
    res = requests.get(url)
    data = json.loads(res.text)
    for i in data["data"]["ipv4_downstreams"]:
      bgpOut += "  AS{} | {} | {} | {}\n".format(i["asn"],i["name"],i["description"],i["country_code"])
    ### IXs
    bgpOut += "\n[ IXs ]\n"
    url = 'https://api.bgpview.io/asn/{}/ixs'.format(asn)
    res = requests.get(url)
    data = json.loads(res.text)
    for i in data["data"]:
      bgpOut += "    IX ID: {}\n".format(i["ix_id"])
      bgpOut += "     Name: {}\n".format(i["name"])
      bgpOut += "Full Name: {}\n".format(i["name_full"])
      bgpOut += "  Country: {}\n".format(i["country_code"])
      bgpOut += "     City: {}\n".format(i["city"])
      bgpOut += "     IPv4: {}\n".format(i["ipv4_address"])
      bgpOut += "     IPv6: {}\n".format(i["ipv6_address"])
      bgpOut += "    Speed: {}\n\n".format(i["speed"])
    return "<pre><code>"+bgpOut+"</code></pre>"
  except Exception as aiEx:
    await crashLog(event,aiEx)

async def bgpViewPrefix(room,event):
  await aiLog(event)
  args = event.body.split()
  prefix = args[1]
  try:
    bgpOut = ""
    url = 'https://api.bgpview.io/prefix/{}'.format(prefix)
    res = requests.get(url)
    data = json.loads(res.text)
    if data["status"] == "ok":
        bgpOut += "[ Prefix Info ]\n\n"
        bgpOut += " PREFIX...: {}\n".format(data["data"]["prefix"])
        bgpOut += " NAME.....: {}\n".format(data["data"]["name"])
        bgpOut += " DESC.....: {}\n".format(data["data"]["description_short"])
        bgpOut += " ADDRESS..: "+" ".join(data["data"]["owner_address"]) + "\n"
        bgpOut += " ALLOCATED: {}\n".format(data["data"]["rir_allocation"]["date_allocated"])
        bgpOut += "\n[ ASNs ]\n\n"
        for i in data["data"]["asns"]:
            bgpOut += " ASN......: AS{}\n".format(i["asn"])
            bgpOut += " Name.....: {}\n".format(i["name"])
            bgpOut += " Desc.....: {}\n".format(i["description"])
            bgpOut += " Country..: {}\n".format(i["country_code"])
            bgpOut += " Upstreams:\n"
            for u in i["prefix_upstreams"]:
                bgpOut += "   AS{} | {} | {} | {}\n".format(u["asn"],u["name"],u["description"],u["country_code"])
    return "<pre><code>"+bgpOut+"</code></pre>"
  except Exception as aiEx:
    await crashLog(event,aiEx)

async def getMACVendor(room,event):
  await aiLog(event)
  args = event.body.split()
  try:
    mac = args[1]
    url = 'https://api.macvendors.com/{}'.format(mac)
    res = requests.get(url)
    data = res.text
    if len(data) > 0:
      return "Vendor: " + data
    else:
      return "No data!"
  except Exception as aiEx:
    await crashLog(event,aiEx)

async def shodanGetIP(banner):
    if 'ipv6' in banner:
        return banner['ipv6']
    return banner['ip_str']

async def shodanSearch(room,event):
  # Show the host information in a user-friendly way and try to include
  # as much relevant information as possible.
  try:
    await aiLog(event)
    args = event.body.split()
    search_term = args[1]
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

async def headerGrab(room,event):
  try:
    await aiLog(event)
    args = event.body.split()
    url = args[1]
    if url[0:4] != "http":
      url = "http://" + url
    rUA = await getLine("assets/useragents.txt") # Random User Agent
    rUA = rUA.split("\n")[0]
    headers = { 'User-Agent': rUA }
    r = requests.get(url, headers=headers, timeout=15, verify=False)
    h = r.headers
    headerOut = ""
    headerOut += "URL: {}\n".format(url)
    headerOut += " UA: {}\n".format(rUA)
    headerOut += "--------------------\n"
    headerOut += " Status: {}\n".format(r.status_code)
    #print(type(r.is_redirect))
    if r.is_redirect:
        headerOut += " Redirect: True\n"
    for hK, hV in h.items():
        headerOut += " {}: {}\n".format(hK,hV)
    
    headerOut += " Content-Length: {}".format(len(r.text))
    return "<pre><code>"+headerOut+"</code></pre>"

  except Exception as aiEx:
    await crashLog(event,aiEx)
    return "<pre><code>No Response!</code></pre>"

async def await resolver(host_name):
  host_ip = socket.gethostbyname(host_name) 
  return host_ip

async def resolveHost(room,event):
  try:
    await aiLog(event)
    args = event.body.split()
    host_name = args[1]
    host_ip = await resolver(host_name) 
    return "<pre><code>"+host_ip+"</code></pre>"
  except Exception as aiEx:
    await crashLog(event,aiEx)
    return "<pre><code>Couldn't resolve IP!</code></pre>"

async def gn(ip):
  gnapi = GreyNoise()
  noise = gnapi.ip(ip)
  gnOut = ""
  if 'seen' in noise:
    gnOut += "IP: {}\n".format(ip)
    gnOut += "Seen: {}\n".format(noise['seen'])
    if 'classification' in noise:
      gnc = noise['classification']
    else:
      return gnOut
    if gnc == "malicious":
      gnOut += "Classification: {}\n".format(gnc)
      gnOut += "Tags:\n"
      for tag in noise['tags']:
        gnOut += "- {}\n".format(tag)
    else:
      gnOut += "Classification: {}\n".format(gnc)
      if 'tags' in noise:
        gnOut += "Tags:\n"
        for tag in noise['tags']:
          gnOut += "- {}\n".format(tag)
  else:
    gnOut = "No results :("
  return gnOut

async def gnWrapper(room,event):
  try:
    await aiLog(event)
    args = event.body.split()
    searchIP = args[1]
    ip = ""
    if await valid_ip(searchIP):
      ip = searchIP
    else:
      ip = await resolver(searchIP)
    gnR = gn(ip)
    if gnR:
      return "<pre><code>"+gnR+"</code></pre>"
  except Exception as aiEx:
    await crashLog(event,aiEx)
    return "<pre><code>No Results!</code></pre>"
