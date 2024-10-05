import requests
import json
import time
try:
    from core.helper import *
except ImportError:
    from helper import *

async def bgpViewASN(room, event, cmdArgs):
  """
  !asn - Search an asn on BGPview
  """
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
  """
  !prefix - Search a prefix on BGPview
  """
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
