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

def helpCB(room, event):
    aiLog(event)
    helpFile = readFile('assets/helpfile.txt')
    return helpFile

def testCB(room,event):
    aiLog(event)
    return "Test Success!"

def archCB(room, event):
    aiLog(event)
    s = event.sender
    out = "Hey {}, use this guide! https://gist.github.com/netspooky/cad9a183daf3dfcbc677221ff452c15b".format(s)
    return out

def ballCB(room, event):
    aiLog(event)
    ball   = getLine("assets/8ball.txt")
    return ball

def skrtCB(room, event):
    aiLog(event)
    return "This message requires Matrix Gold to view"

def stressedCB(room, event):
    aiLog(event)
    dStressTip = getLine("assets/stressed.txt")
    return dStressTip

def cryptoCB(room,event):
    args = event.body.split()
    coin  = args[1]
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
            crashLog(event,aiEx)
