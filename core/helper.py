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

def loadYML(infile):
  with open(infile,'r') as stream:
    try:
      data = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
      print(exc)
  return data

# Global 
SECRETS  = loadYML('secrets.yml') # Disabled to test
#USERNAME = SECRETS["secrets"]["username"]
#PASSWORD = SECRETS["secrets"]["password"]
#SERVER   = SECRETS["secrets"]["server"] 

startTime = ""

def botInit():
    global startTime
    print(BANNER)
    startTime = 'Start: {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())
    print("[+] {}".format(startTime))
    print("[+] Setting up...")
    print("[+] Connecting as "+cPNK+"@"+USERNAME+":"+SERVER[8:]+e)
    initbot = MatrixBotAPI(USERNAME, PASSWORD, SERVER)
    return initbot

# Use these to wrap the send_html output!
fmt1 = "<pre><code>"
fmt2 = "</code></pre>"

### Returns current timestamp
def getTime():
    now = datetime.datetime.now()
    tstamp = now.strftime("%Y-%m-%d %H:%M:%S")
    return tstamp

### verify that a link is a valid google search url - needed for osint/degoogler function
def verify_google(url):
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
def make_google_link(query):
    normalized_query = re.sub(r' |%20', '+', query)
    normalized_query = re.sub(r'\"', '%22', normalized_query)
    url = "https://google.com/search?q=%s" % normalized_query
    return url

### This is a general command wrapper for only getting digits from a given string
def getDigits(someText):
    cleaned = re.sub("\D", "", someText)
    return cleaned

### Check if an IP is valid
def valid_ip(address):
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False

### Get reaction
# yay and nay are the categories

nayList = ["(￣。￣)","(￣ー￣)","(︶︹︺)","(◕ ︵ ◕)","(´◉◞౪◟◉)"]
yayList = ["\\(◕ ◡ ◕\\)","(◕‿◕✿)","(≧ω≦)","(´・ω・｀)",]

def getFace(mood):
    if mood == "yay":
        mood = random.choice(yayList)
    if mood == "nay":
        mood = random.choice(nayList)
    return mood

### Handler for all commands that return a random line from a file
def getLine(file):
    with open(file,"r") as f:
        lines = f.readlines()
        line  = random.choice(lines)
    return line

def readFile(file):
    with open(file,"r") as f:
        lines = f.readlines()
        output = ''.join(lines)
    return output

### If you need logging, this needs to be redone haha
def aiLog(event):
    print(event)

### NEEDS WORK ###
def crashLog(event,eLog):
    tstamp = getTime()
    print("Crashed at {}: {}".format(tstamp, eLog))
