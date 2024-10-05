import requests
import json

try:
    from core.helper import *
except ImportError:
    from helper import *

# !fakeid - Get random user data
async def fakeID(room, event, cmdArgs):
    res = requests.get('http://randomuser.me/api/')
    dataj = json.loads(res.text)
    data  = dataj['results'][0]
    output = ""
    output += "<h3>"
    output += f"{data['name']['first']} {data['name']['last']}</h3>"
    loc  = data['location']
    locc = loc['coordinates']
    loct = loc['timezone']
    output += f"{loc['street']['number']} {loc['street']['name']}, {loc['city']}, {loc['state']} {loc['postcode']}<br>"
    output += '<pre><code>--- Info ---\n'
    output += f"Age........: {data['dob']['age']}\n"
    output += f"DOB........: {data['dob']['date']}\n"
    output += f"Timezone...: GMT {loct['offset']} {loct['description'] }\n"
    output += f"Geo........: {locc['latitude']},{locc['longitude']}\n\n"
    output += '--- Contact Information ---\n'
    output += f"Phone......: {data['phone']}\n"
    output += f"Cell.......: {data['cell']}\n"
    output += f"Email......: {data['email']}\n\n"
    output += '--- User Data ---\n'
    output += f"Username...: {data['login']['username']}\n"
    output += f"Password...: {data['login']['password']}\n"
    output += f"Salt.......: {data['login']['salt']}\n"
    output += f"MD5........: {data['login']['md5']}\n"
    output += f"SHA1.......: {data['login']['sha1']}\n"
    output += f"SHA256.....: {data['login']['sha256']}\n"
    output += f"UUID.......: {data['login']['uuid']}\n"
    output += f"Registered.: {data['registered']['date']}\n"
    output += f"Account Age: {data['registered']['age']} years\n" 
    output += f"Profile Pic: {data['picture']['large']}\n"
    output += '</code></pre>'
    return output
