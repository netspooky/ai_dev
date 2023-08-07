### OSINT Commands
# Anything OSINT related
try:
    from core.helper import *
except ImportError:
    from helper import *
import re

#-> !cid <number>
async def cidSearch(room, event, cmdArgs):
    initialNum    = cmdArgs[0]
    phoneNumber   = await getDigits(initialNum)
    api_key = SECRETS["keys"]["twilio"]
    if len(api_key) == 0:
        return "Please set up a Twilio API key!"
    url = f"https://{api_key}@lookups.twilio.com/v1/PhoneNumbers/{phoneNumber}?Type=carrier"
    res = requests.get(url)
    data = json.loads(res.text)
    out = ""
    try:
        if data['carrier']:
            out += f"Results for: {data['phone_number']}\n\n"
            out += f"Carrier: {data['carrier']['name']}\n"
            out += f"Type: {data['carrier']['type']}\n"
            out += f"Caller name: {data['caller_name']}\n"
            out += f"Country Code: {data['country_code']}\n"
            return f"<pre><code>{out}</code></pre>"
    except Exception as aiEx:
        await crashLog(event,aiEx)
        return f"<pre><code>Something broke :(\n{aiEx}</code></pre>"

#-> !dg <url>
# later expand to a strip function that detects what kind of link it is
# uses verify_google function from helper.py
# TODO write a wrapper, have this return false and then send message based on that?
async def degoogle(room, event, cmdArgs):
    try:
        if len(cmdArgs) >= 1:
            url = cmdArgs[0]
        else:
            text = 'usage: !dg <google search result url> to degoogle a link and extract just the target url!'
            return '<pre><code>' + text + '</code></pre>'
        if await verify_google(url):
            result = False
            segments = re.split('(&q|url|usg|sa|url\?q)=', url)
            if segments:
                for i in range(1, len(segments)):
                    segment = segments[i]
                    if len(segment) >= 12:
                        if segment[0:4] == 'http':
                            validate_segment = urllib.parse.unquote(segment)
                            if (validate_segment[0:7] == 'http://' or validate_segment[0:8] == 'https://'):
                                if re.match(r'^https?://[\w\-]+\.[\w\-]+', validate_segment):
                                    result = segment[0:-1] if segment[-1] == '&' else segment

                                    # selective url decoding + re-encoding
                                    result = re.sub(r'%20', '+', result)
                                    decoded = urllib.parse.unquote(result)
                                    decoded = re.sub(r'\|', '%7C', decoded)
                                    decoded = re.sub(r'\"', '%22', decoded)
                                    decoded = re.sub(r'\>', '%3E', decoded)
                                    decoded = re.sub(r'\<', '%3C', decoded)                      

                                    degoogled = decoded
                                    return '<pre><code>' + degoogled + '</code></pre>'
                if not result:
                    text = 'failed to extract url!'
                    return '<pre><code>' + text + '</code></pre>'
        else:
            text = 'not a valid google search result link!'
            return '<pre><code>' + text + '</code></pre>'
    except Exception as aiEx:
        text = 'Something broke :('
        await crashLog(event,aiEx)
        return '<pre><code>' + text + '</code></pre>'

# !gs <query>
# search google for your query and return all cleaned results + descriptions
async def degoogle_all(room, event, cmdArgs):
    try:
        args = event.body.split()
        if len(args) >= 2:
            query = args[1]
            if len(args) >= 3:
                for i in range(2, len(args)):
                    query += " " + args[i]
                if query[-1] == " ":
                    query = query[0:-1]
        else:
            text = 'usage: !gs <query> to search google and return sanitized result links!'
            return '<pre><code>' + text + '</code></pre>'

        url = await make_google_link(query)
        r = requests.get(url)
        #match_result_segment = r'<a href="/url\?q=http.+?(?="><div)"><div class="[A-Za-z\d ]+">.*?(?=<div)'
        match_result_segment = r'<a href="/url\?q=http.+?(?="><[spandiv]{3,4})"><[spandiv]{3,4} class="[A-Za-z\d ]+">.*?(?=<[spandiv]{3,4})'
        matches = re.findall(match_result_segment, r.text)
        
        if matches:

            valid_matches = []
            
            for match in matches:
                #if match[-6:] == '</div>':
                if match[-6:] == '</div>' or match[-7:] == '</span>':
                    valid_matches.append(match)

            if valid_matches:
                result_block = [] # append dicts, each w url and desc

                for match in valid_matches:
                    url = ""
                    desc = ""
                    find_url = re.split('<a href="/url\?q=|&amp;(sa|usg|ved)=|"><spandiv]{3,4}', match)
                    for segment in find_url:
                        if segment and segment[0:4] == 'http':
                            url = segment
                    if not url:
                        continue
                    else:
                        find_desc = re.split('<[spandiv]{3,4} class=".+?(?=">)">|</[spandiv]{3,4}>', match)
                        for segment in find_desc:
                            if segment and segment[0] != "<":
                                desc = segment
                    if url and desc:
                        url = re.sub(r'%20', '+', url)
                        url = urllib.parse.unquote(url)
                        url = re.sub(r'\|', '%7C', url)
                        url = re.sub(r'\"', '%22', url)
                        url = re.sub(r'\>', '%3E', url)
                        url = re.sub(r'\<', '%3C', url)
                        if url[-1] == '.':
                            url = url[0:-1] + '%2E'
                        desc = re.sub(r'&amp;', '&', desc)
                        # possibly others in the future ^^^

                        result = {'desc': desc, 'url': url}
                        result_block.append(result)

                
                if result_block:
                    final_string = "-- search results --\n\n"
                    for result in result_block:
                        final_string += result['desc'] + '\n' + result['url'] + '\n\n'
                    if final_string[-2:] == '\n\n':
                        final_string = final_string[:-2]

                    return '<pre><code>' + final_string + '</code></pre>'
                    
        else:
            text = "no results"
            return '<pre><code>' + text + '</code></pre>'
    except Exception as aiEx:
        text = 'Something broke :('
        await crashLog(event,aiEx)
        return '<pre><code>' + text + '</code></pre>'

# Get random user data
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

async def vtSearch(room, event, cmdArgs):
    #SECRETS = await loadYML('secrets.yml')
    vtApiKey = SECRETS["keys"]["virus_total"]
    if len(vtApiKey) == 0:
        return "Please set up a Virus Total API key!"
    vtHeaders = {'x-apikey': vtApiKey}
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
        vtExif   = vtd['exiftool']
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
