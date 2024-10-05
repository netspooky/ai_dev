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
