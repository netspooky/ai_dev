# This module is unused because it was rolled into another library outside of ai
try:
    from core.helper import *
except ImportError:
    from helper import *
import re

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

