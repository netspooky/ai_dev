### OSINT Commands
# Anything OSINT related
try:
    from core.helper import *
except ImportError:
    from helper import *
import re

#-> !cid <number>
async def cidSearch(room, event):
    await aiLog(event)
    args = event.body.split()
    initialNum    = args[1]
    phonenumber   = await getDigits(initialNum)

    # This is an easier way of accessing this api which was used in Wish
    #SECRETS = await loadYML('secrets.yml')
    api_key = SECRETS["keys"]["twilio"]
    if len(api_key) == 0:
        return "Please set up a Twilio API key!"
    url = 'https://'+api_key+'@lookups.twilio.com/v1/PhoneNumbers/{}?Type=carrier'.format(phonenumber)

    res = requests.get(url)

    data = json.loads(res.text)
    # print(data) # For debug 
    try:
        if data['carrier']:
            carrier_name = data['carrier']['name']
            carrier_type = data['carrier']['type']
            caller_name  = data['caller_name']
            country_code = data['country_code'] 
            phone_number = data['phone_number']
            text = '''
            Results for: {}\n
            
            Carrier: {}
            Type: {}
            Caller name: {}
            Country Code: {}
            '''.format(phone_number, carrier_name, carrier_type, caller_name, country_code)
            return '<pre><code>' + text + '</code></pre>'
    except Exception as aiEx:
        text = 'Something broke :('
        await crashLog(event,aiEx)
        return '<pre><code>' + text + '</code></pre>'

#-> !dg <url>
# later expand to a strip function that detects what kind of link it is
# uses verify_google function from helper.py
# TODO write a wrapper, have this return false and then send message based on that?
async def degoogle(room, event):
    try:
        await aiLog(event)
        args = event.body.split()
        if len(args) >= 2:
            url = args[1]
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
async def degoogle_all(room, event):
    try:
        await aiLog(event)
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
async def fakeID(room, event):
    await aiLog(event)
    url = 'http://randomuser.me/api/'
    res = requests.get(url)
    data = json.loads(res.text)
    #print(data)
    output = ""
    
    ### Basic info
    output += "<h3>"
    #nameTitle = data['results'][0]['name']['title']
    nameFirst = data['results'][0]['name']['first']
    nameLast  = data['results'][0]['name']['last']
    nameFull  = nameFirst + " " + nameLast
    output    += nameFull + "</h3>"
    fakeDOB   = data['results'][0]['dob']['date']
    fakeAge   = data['results'][0]['dob']['age']

    ### Location Info 
    locStreet = data['results'][0]['location']['street']
    locCity   = data['results'][0]['location']['city']
    locState  = data['results'][0]['location']['state']
    locPostal = data['results'][0]['location']['postcode']
    locLat    = data['results'][0]['location']['coordinates']['latitude']
    locLon    = data['results'][0]['location']['coordinates']['longitude']
    locTZ     = data['results'][0]['location']['timezone']['offset'] # GMT + 
    locDesc   = data['results'][0]['location']['timezone']['description'] 
    locFullTZ = "GMT "+locTZ+" "+locDesc
    output += str(locStreet["number"]) + " " + locStreet["name"] + " " + locCity + " " + locState + str(locPostal) +'<br>'
    output += '<pre><code>--- Info ---\n'
    output += 'Age........: ' + str(fakeAge) + '\n'
    output += 'DOB........: ' + fakeDOB + '\n'
    output += 'Timezone...: ' + locFullTZ + '\n'
    output += 'Geo........: ' + locLat + "," + locLon +'\n'
    output += '\n'

    # contact
    output += '--- Contact ---\n'
    conPhone  = data['results'][0]['phone']
    conCell   = data['results'][0]['cell']
    conEmail  = data['results'][0]['email']
    output += 'Phone......: ' + conPhone + '\n'
    output += 'Cell.......: ' + conCell  + '\n'
    output += 'Email......: ' + conEmail + '\n'
    output += '\n'

    # Userdata
    output += '--- User Data ---\n'
    usrUUID   = data['results'][0]['login']['uuid']
    usrUSER   = data['results'][0]['login']['username']
    usrPASS   = data['results'][0]['login']['password']
    usrSALT   = data['results'][0]['login']['salt']
    usrMD5    = data['results'][0]['login']['md5']
    usrSHA1   = data['results'][0]['login']['sha1']
    usrSHA256 = data['results'][0]['login']['sha256']
    usrRgDate = data['results'][0]['registered']['date']
    usrAccAge = data['results'][0]['registered']['age']
    usrPic    = data['results'][0]['picture']['large']
    output += 'Username...: ' + usrUSER + '\n'
    output += 'Password...: ' + usrPASS + '\n'
    output += 'Salt.......: ' + usrSALT + '\n'
    output += 'MD5........: ' + usrMD5 + '\n'
    output += 'SHA1.......: ' + usrSHA1 + '\n'
    output += 'SHA256.....: ' + usrSHA256 + '\n'
    output += 'Registered.: ' + usrRgDate + '\n'
    output += 'Account Age: ' + str(usrAccAge) + ' years\n'
    output += 'Profile Pic: ' + usrPic + '\n'
    output += '</code></pre>'
    return output

async def vtSearch(room, event):
    #SECRETS = await loadYML('secrets.yml')
    vtApiKey = SECRETS["keys"]["virus_total"]
    if len(vtApiKey) == 0:
        return "Please set up a Virus Total API key!"
    vtHeaders = {'x-apikey': vtApiKey}
    await aiLog(event)
    try:
      args     = event.body.split()
      vtHash   = args[1]
      vtOut    = ""
      url      = 'https://www.virustotal.com/api/v3/files/{}'.format(vtHash)
      res      = requests.get(url, headers=vtHeaders)
      data     = json.loads(res.text)
      vtd      = data["data"]["attributes"]
      vtID     = data["data"]["id"]
      vtMagic  = vtd["magic"]
      vtMD5    = vtd["md5"]
      vtSHA1   = vtd["sha1"]
      vtSHA256 = vtd["sha256"]
      vtTags   = vtd["tags"]
      vtTyped  = vtd["type_description"]
      aRes = data["data"]["attributes"]["last_analysis_results"]
      vtOut += "--- File Meta ---\n"
      vtOut += " VTID....: {}\n".format(vtID)
      vtOut += " Magic...: {}\n".format(vtMagic)
      vtOut += " MD5.....: {}\n".format(vtMD5)
      vtOut += " SHA1....: {}\n".format(vtSHA1)
      vtOut += " SHA256..: {}\n".format(vtSHA256)
      vtOut += " Type....: {}\n".format(vtTyped)
      vtOut += " Tags....: {}\n".format(vtTags)
      if "exiftool" in vtd:
        vtExif   = vtd["exiftool"]
        vtOut += "\n--- Exif Data ---\n"
        for eK, eV in vtExif.items():
            vtOut += " {}: {}\n".format(eK,eV)
        vtOut += "\n--- Detections ---\n"
      for i in aRes:
          eRes = aRes[i]["result"]
          eName = aRes[i]["engine_name"]
          if eRes != None:
              vtOut += " {}: {}\n".format(eName,eRes)
          else:
              continue
      stats = data["data"]["attributes"]["last_analysis_stats"]
      vtOut += "\n--- Stats ---\n"
      for s, v in stats.items():
          vtOut += " {}: {}\n".format(s,v)
      vtOut += "\nLINK: {}".format(data["data"]["links"]["self"])
      return '<pre><code>' + vtOut + '</code></pre>'
    except Exception as aiEx:
      text = 'No Results or API Key Exhausted!'
      await crashLog(event,aiEx)
      return '<pre><code>' + text + '</code></pre>'
