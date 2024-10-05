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

