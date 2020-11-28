### Media Commands
try:
    from core.helper import *
except ImportError:
    from helper import *

#-> !yt <search string>
def ytSearch(room, event):
    aiLog(event)
    args = event.body.split()
    api_key = SECRETS["keys"]["youtube_api"]
    if len(api_key) == 0:
        return "Please set up a Youtube API key!"
    try:
        searchString = ''
        for arg in args[1:]:
            searchString += arg + '+'
            
        url = 'https://www.googleapis.com/youtube/v3/search?part=snippet&type=video&maxResults=5&q={}&key={}'.format(searchString, api_key)
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
            return '{}<br>https://www.youtube.com/watch?v={}'.format(title_and_desc,data['items'][0]['id']['videoId'])
        else:
            return "https://www.youtube.com/watch?v=KwDrfMCsIwg"
    except Exception as aiEx:
        crashLog(event,aiEx)

 #-> !ud <search string>
def udSearch(room, event):
    aiLog(event)
    args = event.body.split()
    try:
        args.pop(0)
        searchString = ' '.join(args)
        url = 'http://api.urbandictionary.com/v0/define?term={}'.format(searchString)
        res = requests.get(url)
        data = json.loads(res.text)
        keyList = ['definition','example','sound_urls']

        if not data['list']:
            face = getFace('nay')
            return '<h2>{}</h2>'.format(face)
        else:
            udDef = data['list'][0]['definition']
            udExm = data['list'][0]['example']
            udSnd = data['list'][0]['sound_urls'] # def keep an eye on this
            udSound = '\n'.join(udSnd)
            return '<h3>Definition: "'+searchString+'"</h3>'+udDef+'\n'+fmt1+"Sound URLS:\n"+udSound+fmt2
    except Exception as aiEx:
        crashLog(event,aiEx)

# This is down and needs to be reimplemented, can use a text file
def lameInsult(room, event):
    aiLog(event)
    url = "https://evilinsult.com/generate_insult.php?lang=en&type=json"
    try:    
        res = requests.get(url)
        data = json.loads(res.text)
        if 'insult' in data:
            return "<pre><code>{}</code></pre>".format(data['insult'])
    except Exception as aiEx:
        crashLog(event,aiEx)
