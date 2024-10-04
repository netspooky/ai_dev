### Generic helper functions ###################################################
#
# These are imports for all our sub files so all you'll have to do for a
# module is import helper with the following header to take care of everything
#
# try:
#     from core.helper import *
# except ImportError:
#     from helper import *
#try:
#    from core.utils import google_tlds
#except ImportError:
#    from utils import google_tlds

import base64
import random
import datetime
import base64
import urllib.parse
import requests
import json
import re
import socket
import yaml

import os
import magic
import shutil
import aiofiles.os
from PIL import Image

from nio import (Api, AsyncClient, MatrixRoom, RoomMessageText, UploadResponse)
CONFIG_FILE="./credentials.json"

### ANSI Colors ###
cBLK  = "\033[1;30m"
cRED  = "\033[38;5;124m"
cGRN  = "\033[38;5;84m"
cYEL  = "\033[38;5;11m"
cBLUE = "\033[38;5;51m"
cMGNT = "\033[1;35m"
cCYAN = "\033[1;36m"
cWHT  = "\033[1;37m"
cPNK  = "\033[38;5;219m"
cPURP = "\033[38;5;147m"
cGRY  = "\033[38;5;239m"
cLGRY = "\033[38;5;242m"
e     = "\033[0m"

class helperBot:
    def __init__(self):
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            self.client = AsyncClient(config['homeserver'])
            self.client.access_token = config['access_token']
            self.client.user_id = config['user_id']
            self.client.device_id = config['device_id']

### The client object
hBot = helperBot()

def loadYML(infile):
  with open(infile,'r') as stream:
    try:
      data = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
      print(exc)
  return data

SECRETS = loadYML('./secrets.yml')

# Use these to wrap the send_html output!
fmt1 = "<pre><code>"
fmt2 = "</code></pre>"

### Returns current timestamp
async def getTime():
    now = datetime.datetime.now()
    tstamp = now.strftime("%Y-%m-%d %H:%M:%S")
    return tstamp

### verify that a link is a valid google search url - needed for osint/degoogler function
async def verify_google(url):
    find_match = re.match('^(https?://)?(www\.)?(google\.[a-z]{2,3}(\.[a-z]{2})?)/url', url)
    if find_match:
        for match in find_match.groups():
            if match and match[0:6] == 'google':
                domain_segments = re.split('google\.', match)
                tld = domain_segments[1]
                if str(len(tld)) in google_tlds and tld in google_tlds[str(len(tld))]:
                    return True
    else:
        return False

# TODO: add a bot command to just return a google link based on specified query rather than actually running query
# return a valid google search url for a query
async def make_google_link(query):
    normalized_query = re.sub(r' |%20', '+', query)
    normalized_query = re.sub(r'\"', '%22', normalized_query)
    url = "https://google.com/search?q=%s" % normalized_query
    return url

### This is a general command wrapper for only getting digits from a given string
async def getDigits(someText):
    cleaned = re.sub("\D", "", someText)
    return cleaned

### Check if an IP is valid
async def valid_ip(address):
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False

### Get reaction
# yay and nay are the categories

nayList = ["(￣。￣)","(￣ー￣)","(︶︹︺)","(◕ ︵ ◕)","(´◉◞౪◟◉)"]
yayList = ["\\(◕ ◡ ◕\\)","(◕‿◕✿)","(≧ω≦)","(´・ω・｀)",]

async def getFace(mood):
    if mood == "yay":
        mood = random.choice(yayList)
    if mood == "nay":
        mood = random.choice(nayList)
    return mood

### Handler for all commands that return a random line from a file
async def getLine(file):
    with open(file,"r") as f:
        lines = f.readlines()
        line  = random.choice(lines)
    return line

async def readFile(file):
    with open(file,"r") as f:
        lines = f.readlines()
        output = ''.join(lines)
    return output

### Don't use
async def aiLog(event):
    return # This is now covered in the bot class
#    print(event)

### NEEDS WORK ###
async def crashLog(event,eLog):
    tstamp = await getTime()
    print("Crashed at {}: {}".format(tstamp, eLog))

### modified send_file.py example code, should be cleaned up ###
async def send_image(room, image):

    client = hBot.client

    mime_type = magic.from_file(image, mime=True)  # e.g. "image/jpeg"
    if not mime_type.startswith("image/"):
        print("Drop message because file does not have an image mime type.")
        return

    im = Image.open(image)
    (width, height) = im.size  # im.size returns (width,height) tuple

    # first do an upload of image, then send URI of upload to room
    file_stat = await aiofiles.os.stat(image)
    async with aiofiles.open(image, "r+b") as f:
        resp, maybe_keys = await client.upload(
            f,
            content_type=mime_type,  # image/jpeg
            filename=os.path.basename(image),
            filesize=file_stat.st_size)
    if (isinstance(resp, UploadResponse)):
        print("Image was uploaded successfully to server. ")
    else:
        print(f"Failed to upload image. Failure response: {resp}")

    content = {
        "body": os.path.basename(image),  # descriptive title
        "info": {
            "size": file_stat.st_size,
            "mimetype": mime_type,
            "thumbnail_info": None,  # TODO
            "w": width,  # width in pixel
            "h": height,  # height in pixel
            "thumbnail_url": None,  # TODO
        },
        "msgtype": "m.image",
        "url": resp.content_uri,
    }

    try:
        await client.room_send(
            room.room_id,
            message_type="m.room.message",
            content=content
        )
        print("Image was sent successfully")
    except Exception as e:
        print(f"Image send of file {image} failed: {e}")
