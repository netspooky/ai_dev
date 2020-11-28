### Chat Triggers ##############################################################
# You can put whatever you like here, we just had some triggers for the words 
# "skid" and "blackhat"

try:
    from core.helper import *
except ImportError:
    from helper import *

def blackhat(room, event):
    bh = getLine("assets/blackhatquote.txt")
    return "{} {}".format(s, bh)

def skid(room, event):
    skidverb = getLine("assets/skidverb.txt")
    s = event.sender
    return "{}, who are you calling a skid? Heh, do you even {}".format(s, skidverb)
