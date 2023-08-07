import asyncio
from nio import (Api, AsyncClient, MatrixRoom, RoomMessageText)
import time
import json
import os
import core
from core import *
import datetime
 
CONFIG_FILE = "credentials.json"
COMMAND_TOKEN = "!"
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
cmdDict = { 
            "8ball": {
                "func": core.generic.ballCB,
                "help": "Consult the great oracle. Ask a yes or no question. Returns an answer.",
                "usage": "8ball [question]",
            },
            "arch": {
                "func": core.generic.archCB,
                "help": "Get a guide on installing Arch Linux.",
                "usage": "arch",
            },
            "bgp": {
                "func": core.net.bgpViewASN,
                "help": "Get info on your favorite ASNs!",
                "usage": "bgp [ASXXX]",
            },
            "bssid": {
                "func": core.net.bssid_lookup,
                "help": "Look up a BSSID.",
                "usage": "bssid [XX:XX:XX:XX:XX:XX]",
            },
            "cc": {
                "func": core.generic.cryptoCB,
                "help": "Get USD crypto price for a given coin.",
                "usage": "cc [coin]",
            },
            "cid": {
                "func": core.osint.cidSearch,
                "help": "Look up number on Twilio API",
                "usage": "cid [number]",
            },
            "cve": {
                "func": core.exploit.cveSearch,
                "help": " Return public exploits for a given CVE",
                "usage": "cve [CVE-xxxx-xxxx]",
            },
            "dns": {
                "func": core.net.secTrails,
                "help": "Get detailed DNS info using the SecTrails API. Warning: This is tied to an API key that has limited uses.",
                "usage": "dns [domain]",
            },
            "dnsd": {
                "func": core.net.dnsdumpster,
                "help": "Get DNS info + a network map for a given domain",
                "usage": "dnsd [domain]",
            },
            "dnsd2": {
                "func": core.net.dnsdumpster2,
                "help": "Get DNS info + a network map for a given domain, 2023 edition",
                "usage": "dnsd2 [domain]",
            },
            "fakeid": {
                "func": core.osint.fakeID,
                "help": "Returns a whole fake identity",
                "usage": "fakeid",
            },
            "fuzz": {
                "func": core.exploit.getFuzz,
                "help": "Get a fuzzing string. Warning, kind of wonky",
                "usage": "fuzz",
            },
            "gn": {
                "func": core.net.gnWrapper,
                "help": "Search Greynoise for an IP",
                "usage": "gn [ip address]",
            },
            "head": {
                "func": core.net.headerGrab,
                "help": "Grab headers from a domain",
                "usage": "head [domain]",
            },
            "host": {
                "func": core.net.resolveHost,
                "help": "Resolve IP from a domain name",
                "usage": "host [ip]",
            },
            "inspire": {
                "func": core.media.inspire,
                "help": "Get an image from inspirobot.me",
                "usage": "",
            },
            "ip": {
                "func": core.net.ipinfo,
                "help": "Look up an IP address",
                "usage": "ip [ip]",
            },
            "mac": {
                "func": core.net.getMACVendor,
                "help": "Get vendor for a given mac address", # Note this can use ouisieee
                "usage": "mac [mac address]",
            },
            "os": {
                "func": core.generic.obliqueCB,
                "help": "Get an oblique strategy",
                "usage": "os",
            },
            "prefix": {
                "func": core.net.bgpViewPrefix,
                "help": "Look up an IP Prefix / CIDR Block",
                "usage": "prefix X.X.X.X/X",
            },
            "reversi": {
                "func": core.exploit.reversi,
                "help": "Generate Linux 64 bit one liner reverse shell (broken rn)",
                "usage": "reversi [IP] [PORT]",
            },
            "shodan": {
                "func": core.net.shodanSearch,
                "help": "Search shodan for an IP",
                "usage": "shodan [IP]",
            },
            "skrt": {
                "func": core.generic.skrtCB,
                "help": "Ping me!",
                "usage": "skrt",
            },
            "stressed": {
                "func": core.generic.stressedCB,
                "help": "Get a tip on what to do if you are stressed.",
                "usage": "stressed",
            },
            "test": {
                "func": core.generic.testCB,
                "help": "Do a test",
                "usage": "test",
            },
            "ud": {
                "func": core.media.udSearch,
                "help": "Look up a term on Urban Dictionary",
                "usage": "ud [search string]",
            },
            "uss": {
                "func": core.net.urlScanSearch,
                "help": "Search for a domain on urlscan",
                "usage": "uss [domain]",
            },
            "vt": {
                "func": core.osint.vtSearch,
                "help": "Search an MD5, SHA1 or SHA256 hash on VirusTotal",
                "usage": "vt [hash]",
            },
            "w": {
                "func": core.net.wpRandom,
                "help": "Get a random Wikipedia page",
                "usage": "w",
            },
            "x64": {
                "func": core.asm.x64Handler,
                "help": "Emulate some shellcode",
                "usage": "x64",
            },
            "xss": {
                "func": core.exploit.getXSS,
                "help": "Get an XSS payload (kinda wonky)",
                "usage": "xss",
            },
            "yt": {
                "func": core.media.ytSearch,
                "help": "Look up a Youtube video",
                "usage": "yt [search string]",
            },
            #"!ddg": core.osint.degoogle, # - I have no idea about this error: name 'google_tlds' is not defined
            #"!dgs": core.osint.degoogle_all, # - Can just implement the degoogle library
}

class Bot:
    def __init__(self, cmds=cmdDict):
        print(BANNER)
        print("Authenticating...")
        self.cmdToken = COMMAND_TOKEN
        self.commands = cmds
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            self.client = AsyncClient(config['homeserver'])
            self.client.access_token = config['access_token']
            self.client.user_id = config['user_id']
            self.client.device_id = config['device_id']

    def getTime(self):
        now = datetime.datetime.now()
        tstamp = now.strftime("%Y-%m-%d %H:%M:%S")
        return tstamp
    
    def printHelp(self, inCmd):
        # Usage for this
        # ?command -- Gives help on this command
        # <COMMAND_TOKEN>help command -- Gives help on command
        # <COMMAND_TOKEN>help -- Gives general help
        # <COMMAND_TOKEN>h -- Gives general help
        helpOut = ""
        if inCmd in self.commands.keys():
            if len(inCmd) > 0:
                helpOut += f"<h3>{inCmd} Help</h3>"
                helpOut += f"<b>Description:</b> {self.commands[inCmd]['help']}<br>"
                helpOut += f"<b>Usage:</b> <code>{COMMAND_TOKEN}{self.commands[inCmd]['usage']}</code>"
                return helpOut
        else:
            helpOut = "<table><thead><tr><th>Command</th><th>Description</th><th>Example</th></tr></thead><tbody>"
            for command in self.commands.keys():
                helpOut += f"<tr><td>{command}</td><td>{self.commands[command]['help']}</td><td><code>{self.commands[command]['usage']}</code></td></tr>"
            helpOut += "</tbody></table>"
        return helpOut

    async def msgListener(self, room, event):
        # Logging needs to happen here as well as filtering and args
        botResponse = 0
        if event.server_timestamp > INIT_TIME:
            timeNow = self.getTime()
            if event.body[0] == "?": # This handles a help command with the syntax `?command`
                print(f"{timeNow}: {room.room_id} ({room.name}) {event}")
                cmdArgs = event.body.split()
                helpCmd = cmdArgs[0].split("?")[1]
                botResponse = self.printHelp(helpCmd)
            elif event.body[0] == self.cmdToken:
                print(f"{timeNow}: {room.room_id} ({room.name}) {event}")
                cmdArgs = event.body.split()
                cmd = cmdArgs[0].split(self.cmdToken)[1]
                cmdArgs.pop(0)
                if cmd == "help":
                    helpCmd = ""
                    if len(cmdArgs) > 0:
                        helpCmd = cmdArgs[0]
                    botResponse = self.printHelp(helpCmd)
                elif cmd in cmdDict.keys():
                    botResponse = await cmdDict[cmd]["func"](room, event, cmdArgs)
        if botResponse != 0:
            await self.client.room_send(
                room_id=room.room_id,
                message_type="m.room.message",
                content={
                    "msgtype": "m.text",
                    "format": "org.matrix.custom.html",
                    "body": botResponse,
                    "formatted_body": botResponse
                }
            )

tBot = Bot(cmds=cmdDict) # Initialize the bot with a dict of callbacks and usage info

async def main():
    tBot.client.add_event_callback(tBot.msgListener, RoomMessageText)
    print("Starting up at {}".format(INIT_TIME))
    await tBot.client.sync_forever(timeout=30000)

asyncio.get_event_loop().run_until_complete(main())

