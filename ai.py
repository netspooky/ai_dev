import asyncio
from nio import (Api, AsyncClient, MatrixRoom, RoomMessageText)
import time
import json
import os
import core
from core import *
 
CONFIG_FILE = "credentials.json"
INIT_TIME   = int(time.time())*1000 # Dumb time hack lol

BANNER = """
((((((/(((((((/((((/((((((((((((((((((((((((((/,,,,,,,,,,,,,,,,,,,*//,,,/,,,,,,
(((((/(((((((*((((((((((((((((((((((((((((((((/.*/(/,,,,,,,,,,,///(/(((,,,*,,,,
(((((/(((((((((((//((((((((((((((((((((((((((*/((((,,,,,,,.,,(**/(((/(,*/,,,,,,
(((((,(((((((((/,((((((((((((((((/((((/(((((/(((((,,,,,,*,.*,*(((((((*,,,,,,,,,
((((((*,,***,,,(((((((((((((((/((((((/(((((((((((*,,,/,/(,./,,/(((((((,,,,,,,,,
((((((((((((((((((((((((((/(/((((((*(((((/((((((/,(,*/ (/,.**,,/,,**/((,,,,,,,,
((((((((((((((((((((((*,*,/((((((*((((((/(((((((./(/(*.(*,.,*,,,,,,,*,/,,,,,,,,
*((((((((((((((((/,,,,,*((((((/,(((((((*(((((((.//(((,.*,,,,*,,,,,,,,,,,,,,,,,.
,,..,,*****,,,,,.,,,*((((((/,,(((((((*,(((((((,,*((((,,,,,,,,,,,,,,.,,,,,,,,,.,
*.,,,,,,,,,,,,,,*(((((((*,,*(((((((,,,((((((/,.**(((,.,,,,,.,,,,,,,,,,,,,,,,,,,
,*,.,,,**//(((((((/,,,,.,/(*./((*,,,,((/(((,,,,/(((*,.,,,,,.,,,,,,,,,,,,,,,,.,,
,,,.,,...,,,,,,,,..,,,..,,*,,,,,,..//,/((*,,,,*,((/,,,,,,,,.,.,,,,,,,.,,,,,,.,,
,,,.,****,,,..,,...,,....,,,,,,..*,.*,/,,,,,.,,/(*,,..,,,,,.,,.,,,,..,,,,,,,,,,
,((((*,.,,,,,,,.,,,.,.....   ..,,.,,,,,,,,,.,,*/,,,,..,,,,,.,.,.,,,,,...,,,,,.,
(((,*(,,,,,.,,,.,./(/(/*,*,.,,.,...,,,,,,,,.,*,,,,, .,,,,,,.,.,,,,,,..,. ,,,,,.
(*((,,,,,,,,,,,,.(####(//*..,,.,.,..., .,,..,,,,,...,,,,,,,,,.,,.,,..,.,..,,,,,
((,,,,.,,,,//...*####/ *(,       ,//,,,.. .,,,,,,..,,,,,...,, ,,.,,..,.,,,,,,,,
(,,,,,,,,,///../######/(((#*  ,(,,..,.,,,,,,,.*. ,,,,,.,.*,...,,,.,.,,,.,,,,.,,
,,,.,,,,,*/(*#.(#######(#,**   * ( //(/*,*/*.*,,,,,, *,,    ..,/. ,.,.,.,,,,,,.
,,,,,,,,,/(**(#############(/(/*##(/###(((((((((((((((..*./(,,//..,*,,,,.,,,,,,
,,,,,,.,,.(((#########(((########(((############(((((/       ./((#,./,.,,.,,,.,
,,,,,,,,,,,./#*#####################################* ,.  (#,#  ((((/(,..,,.,,,
,,,,,,,..,,,,,,(###################################/#,(.  /*### *((#(/....,..,.
,,,,,,,,,,,,,,,,#############################/###########(*/((#####(.,,,,,,..,,
,,.,,,,.....,,,,/###########################(/(###(((/(#(/#######(/(*.,.,,,,*..
,,,.,,.,..,.,,,,(/##########################((((################,(((, ,,.,,,,(,
#,,,,,,,,.,..,,,*(*########################((((###############((#,,,,.,,,,,,,(,
###,,,,,,,,,.,.,.((((###############((#######################./.,,,,.,,,.,,,(.,
######,,,.,,.,*(#(#((*###################(/((##############(.,,.,,..,,,..,,/.((
#########*,.,,.,((###(/(##############((##################,.,.,,..,,,,,.,,(((((
###########*,.,,,.(###((*(#############(((#############(.,,.. ,.,,,,..,.(((((((
#############/.,,.../((((/*#########################(.../*,,.,,,,,.../(((((((((
##/    .(#####(.,,...../((//*(#(#################,*(((*((//(/,, .*,/(,((/,,**//
         .*/(,. .....        ,**((((########(,, . ((/((*((/.   ./(((*((((((((((
  ,//(((((#.....,....              /(((/,      .  *//*((/*     /(*(((((((((((((
 /(((#((/##.....,,....                         . /**((//(/    .((/(((((((((((((
(((###(((##.....,.....                        . /,/((/(((.    .((((((((((((((((
((###((#/##. ...,.....                        .,,/(/(((((.    .((((((((((((((((
(####(##/##   .....                            .//*((((((.     (((\033[38;5;219m/\\/\\/\\/\\/\\/[]\033[0m
"""

### This is where all of the commands are registered
cmdDict = { "!brokencommand": core.helper.getTime, # Broken?
            ### Generic Commands
            "!arch": core.generic.archCB,
            "!help": core.generic.helpCB,
            "!test": core.generic.testCB,
            "!8ball": core.generic.ballCB,
            "!skrt": core.generic.skrtCB,
            "!stressed": core.generic.stressedCB,
            "!cc": core.generic.cryptoCB,
            "!inspire": core.media.inspire,
            ### Exploit Commands
            "!xss": core.exploit.getXSS,
            "!fuzz": core.exploit.getFuzz,
            "!reversi": core.exploit.reversi,
            "!cve": core.exploit.cveSearch,
            ### Net Commands
            "!ip": core.net.ipinfo,
            "!bssid": core.net.bssid_lookup,
            "!dnsd": core.net.dnsdumpster,
            "!bgp": core.net.bgpViewASN,
            "!prefix": core.net.bgpViewPrefix,
            "!mac": core.net.getMACVendor,
            "!shodan": core.net.shodanSearch,
            "!head": core.net.headerGrab,
            "!host": core.net.resolveHost,
            "!gn": core.net.gnWrapper,
            "!dns": core.net.secTrails,
            ### Osint Commands
            "!fakeid": core.osint.fakeID,
            "!cid": core.osint.cidSearch,
            #"!ddg": core.osint.degoogle, # - I have no idea about this error: name 'google_tlds' is not defined
            #"!dgs": core.osint.degoogle_all, # - Can just implement the degoogle library
            "!vt": core.osint.vtSearch,
            "!ud": core.media.udSearch,
            "!w": core.net.wpRandom,
            "!yt": core.media.ytSearch
}

class Bot:
    def __init__(self):
        print(BANNER)
        print("Authenticating...")
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            self.client = AsyncClient(config['homeserver'])
            self.client.access_token = config['access_token']
            self.client.user_id = config['user_id']
            self.client.device_id = config['device_id']

### The client object
tBot = Bot()

async def msgListener(room, event):
    if event.server_timestamp > INIT_TIME:
        if event.body[0] == "!":
            msg = event.body.split()
            cmd = msg[0]
            if cmd in cmdDict.keys():
                print(msg)
                botResponse = await cmdDict[cmd](room, event)
                if botResponse != 0:
                    await tBot.client.room_send(
                        room_id=room.room_id,
                        message_type="m.room.message",
                        content={
                            "msgtype": "m.text",
                            "format": "org.matrix.custom.html",
                            "body": botResponse,
                            "formatted_body": botResponse
                        }
                    )   

async def main():
    tBot.client.add_event_callback(msgListener, RoomMessageText)
    print("Starting up at {}".format(INIT_TIME))
    await tBot.client.sync_forever(timeout=30000)

asyncio.get_event_loop().run_until_complete(main())
