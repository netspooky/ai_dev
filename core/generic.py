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

async def helpCB(room, event, cmdArgs):
    helpFile = await readFile('assets/helpfile.txt')
    return helpFile

async def testCB(room, event, cmdArgs):
    return "Test Success!"

async def archCB(room, event, cmdArgs):
    s = event.sender
    out = "Hey {}, use this guide! https://gist.github.com/netspooky/cad9a183daf3dfcbc677221ff452c15b".format(s)
    return out

async def ballCB(room, event, cmdArgs):
    ball = await getLine("assets/8ball.txt")
    return ball

async def skrtCB(room, event, cmdArgs):
    return "This message requires Matrix Gold to view"

async def stressedCB(room, event, cmdArgs):
    dStressTip = await getLine("assets/stressed.txt")
    return dStressTip

async def obliqueCB(room, event, cmdArgs):
    obliqueStrategy = await getLine("assets/obliquestrategies.txt")
    return obliqueStrategy

async def cryptoCB(room, event, cmdArgs):
    coin = cmdArgs[0]
    if len(coin) > 4:
        return "Not a coin lol"
    else:
        try:
            rOut  = urlopen("https://min-api.cryptocompare.com/data/price?fsym="+coin+"&tsyms=USD")
            rRaw  = rOut.read()
            jOut  = json.loads(rRaw.decode('utf-8'))
            price = str(jOut["USD"])
            coinOut = "{}: ${}".format(coin,price)
            return coinOut
        except Exception as aiEx:
            await crashLog(event,aiEx)
