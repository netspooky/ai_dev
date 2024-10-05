from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI

try:
    from core.helper import *
except ImportError:
    from helper import *

async def dnsdumpster2(room, event, cmdArgs):
    """
    !dnsd2 - DNS Dumpster - 2023 Edition
    """
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
    """
    !dnsd2 - DNS Dumpster
    """
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
