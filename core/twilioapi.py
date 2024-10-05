import requests
import json

try:
    from core.helper import *
except ImportError:
    from helper import *

class TwilioAPI:
    def __init__(self):
        self.api_key = SECRETS["keys"]["twilio"]
        if len(self.api_key) == 0:
            return "Please set up a Twilio API key!"
        else:
            print("[+] Twilio: API Key Loaded!")
    #-> !cid <number>
    async def cid_search(self, room, event, cmdArgs):
        initialNum    = cmdArgs[0]
        phoneNumber   = await getDigits(initialNum)
        url = f"https://{self.api_key}@lookups.twilio.com/v1/PhoneNumbers/{phoneNumber}?Type=carrier"
        res = requests.get(url)
        data = json.loads(res.text)
        out = ""
        try:
            if data['carrier']:
                out += f"Results for: {data['phone_number']}\n\n"
                out += f"Carrier: {data['carrier']['name']}\n"
                out += f"Type: {data['carrier']['type']}\n"
                out += f"Caller name: {data['caller_name']}\n"
                out += f"Country Code: {data['country_code']}\n"
                return f"<pre><code>{out}</code></pre>"
        except Exception as aiEx:
            await crashLog(event,aiEx)
            return f"<pre><code>Something broke :(\n{aiEx}</code></pre>"

TwilioCmd = TwilioAPI()