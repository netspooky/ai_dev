### Media Commands
try:
    from core.helper import *
except ImportError:
    from helper import *

#-> !inspire [no args]
async def inspire(room, event, cmdArgs):
    imgURL = requests.get("https://inspirobot.me/api?generate=true").text
    image = requests.get(imgURL, stream=True)
    image.raw.decode_content = True

    filename = "/tmp/inspirobot.jpeg" # change to not need to touch disk?
    with open(filename, "wb+") as imgFile:
        shutil.copyfileobj(image.raw, imgFile)
    
    await send_image(room, filename)
    return 0

# This is down and needs to be reimplemented, can use a text file
async def lameInsult(room, event, cmdArgs):
    return "Haven't you heard enough insults?"

 #-> !ud <search string>
async def udSearch(room, event, cmdArgs):
    try:
        searchString = ' '.join(cmdArgs)
        url = f"http://api.urbandictionary.com/v0/define?term={searchString}"
        res = requests.get(url)
        data = json.loads(res.text)
        if not data['list']:
            face = await getFace('nay')
            return f"<h2>{face}</h2>"
        else:
            udDef = data['list'][0]['definition']
            udExample = "None"
            udSound = "None"
            if 'example' in data['list'][0]:
                udExample = data['list'][0]['example']
            if 'sound_urls' in data['list'][0]:
                udSndUrls = '\n'.join(data['list'][0]['sound_urls'])
                udSound = f"{fmt1}Sound URLs:\n{udSndUrls}{fmt2}"
            out = ""
            out += f"<h3>Definition: '{searchString}'</h3> {udDef}<br>"
            out += f"<h4>Example</h4> {udExample}<br>"
            out += f"<h4>Sound URLs</h4> {udSound}"
            return out
    except Exception as aiEx:
        await crashLog(event,aiEx)
        return f"<pre><code>Oops!\n{aiEx}</code></pre>"

#-> !yt <search string>
async def ytSearch(room, event, cmdArgs):
    api_key = SECRETS["keys"]["youtube_api"]
    if len(api_key) == 0:
        return "Please set up a Youtube API key!"
    try:
        searchString = ''
        for arg in cmdArgs:
            searchString += arg + '+'
        url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&type=video&maxResults=5&q={searchString}&key={api_key}"
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
            return "https://www.youtube.com/watch?v=KwDrfMCsIwg"
    except Exception as aiEx:
        await crashLog(event,aiEx)
