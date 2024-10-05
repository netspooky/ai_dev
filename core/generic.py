### Generic Function Callbacks
# These are all the functions that are super common and likely to not change
# 
try:
    from core.helper import *
except ImportError:
    from helper import *

import json
import re 
from urllib.request import urlopen

class aiGenericCmds:
    def __init__(self):
        self.init = True
    async def archCB(self, room, event, cmdArgs):
        return f"Hey {event.sender}, use this guide! https://gist.github.com/netspooky/cad9a183daf3dfcbc677221ff452c15b"
    async def ballCB(self, room, event, cmdArgs):
        return await getLine("assets/8ball.txt")
    async def cryptoCB(self, room, event, cmdArgs):
        coin = cmdArgs[0]
        if len(coin) > 4:
            return "Not a coin lol"
        else:
            try:
                rOut  = urlopen("https://min-api.cryptocompare.com/data/price?fsym="+coin+"&tsyms=USD")
                rRaw  = rOut.read()
                jOut  = json.loads(rRaw.decode('utf-8'))
                price = str(jOut["USD"])
                coinOut = f"{coin}: ${price}"
                return coinOut
            except Exception as aiEx:
                await crashLog(event,aiEx)
    async def obliqueCB(self, room, event, cmdArgs):
        return await getLine("assets/obliquestrategies.txt")
    async def skrtCB(self, room, event, cmdArgs):
        return "This message requires Matrix Gold to view"
    async def stressedCB(self, room, event, cmdArgs):
        return await getLine("assets/stressed.txt")
    async def testCB(self, room, event, cmdArgs):
        return "Test Success!!!!"

aiGeneric = aiGenericCmds()
