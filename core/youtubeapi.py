import requests
import json

try:
    from core.helper import *
except ImportError:
    from helper import *

class YoutubeAPI:
    def __init__(self):
        self.api_key = SECRETS["keys"]["youtube_api"]
        if len(self.api_key) == 0:
            print("[-] Please set up a Youtube API key!")
        else:
            print("[+] Youtube: API Key Loaded!")
    #-> !yt <search string>
    async def yt_search(self, room, event, cmdArgs):
        if self.api_key:
            try:
                searchString = ''
                for arg in cmdArgs:
                    searchString += arg + '+'
                url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&type=video&maxResults=5&q={searchString}&key={self.api_key}"
                res = requests.get(url)
                data = json.loads(res.text)
                
                if data['pageInfo']['totalResults'] > 0:
                    title = data['items'][0]['snippet']['title']
                    desc = data['items'][0]['snippet']['description']
                    title_and_desc = ""
                    #truncate
                    if len(desc) > 100:
                       desc = ("%s..." % desc[:96])
                    if not desc: #no hyphen if no description
                        title_and_desc = title
                    else: #separate title and desc with a hyphen
                        title_and_desc = ("<h3>%s</h3><i>%s</i>" % (title, desc))
                    return f"{title_and_desc}<br>https://www.youtube.com/watch?v={data['items'][0]['id']['videoId']}"
                else:
                    return "No Results!"
            except Exception as aiEx:
                await crashLog(event,aiEx)
                return f"<pre><code>Oops!\n{aiEx}</code></pre>"
        else:
            return "Please set up an API key to use this command."

YoutubeCmd = YoutubeAPI()
