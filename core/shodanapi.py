import shodan
import textwrap
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

try:
    from core.helper import *
except ImportError:
    from helper import *

class ShodanAPI:
    def __init__(self):
        self.api_key = SECRETS["keys"]["shodan"]
        if len(self.api_key) == 0:
            print("[-] Please set up a Youtube API key!")
        else:
            print("[+] Youtube: API Key Loaded!")
    async def shodan_get_ip(self, banner):
        if 'ipv6' in banner:
            return banner['ipv6']
        return banner['ip_str']
    async def shodan_search(self, room, event, cmdArgs):
        """
        !shodan - Shodan Search command
        Show the host information in a user-friendly way and try to include
        as much relevant information as possible.
        """
        if self.api_key:
          try:
            search_term = cmdArgs[0]
            api = shodan.Shodan(self.api_key)
            try:
                host = api.host(search_term)
            except:
                return "<pre><code>No results!</code></pre>"
            output  = """"""
            output += await self.shodan_get_ip(host) + '\n'
            if len(host['hostnames']) > 0:
                output += u'{:25s}{}\n'.format('Hostnames:', ';'.join(host['hostnames']))
        
            if 'city' in host and host['city']:
                output += u'{:25s}{}\n'.format('City:', host['city'])
        
            if 'country_name' in host and host['country_name']:
                output += u'{:25s}{}\n'.format('Country:', host['country_name'])
        
            if 'os' in host and host['os']:
                output += u'{:25s}{}\n'.format('Operating System:', host['os'])
        
            if 'org' in host and host['org']:
                output += u'{:25s}{}\n'.format('Organization:', host['org'])
        
            if 'last_update' in host and host['last_update']:
                output += '{:25s}{}\n'.format('Updated:', host['last_update'])
        
            output += '{:25s}{}\n\n'.format('Number of open ports:', len(host['ports']))
        
            # Output the vulnerabilities the host has
            if 'vulns' in host and len(host['vulns']) > 0:
                vulns = []
                for vuln in host['vulns']:
                    if vuln.startswith('!'):
                        continue
                    if vuln.upper() == 'CVE-2014-0160':
                        vulns.append('Heartbleed')
                    else:
                        vulns.append(vuln)
        
                if len(vulns) > 0:
                    output += '{:25s}'.format('Vulnerabilities:')
        
                    for vuln in vulns:
                        output += vuln + '\t'
        
                    output += ''
        
            output += ''
        
            # If the user doesn't have access to SSL/ Telnet results then we need
            # to pad the host['data'] property with empty banners so they still see
            # the port listed as open. (#63)
            if len(host['ports']) != len(host['data']):
                # Find the ports the user can't see the data for
                ports = host['ports']
                for banner in host['data']:
                    if banner['port'] in ports:
                        ports.remove(banner['port'])
        
                # Add the placeholder banners
                for port in ports:
                    banner = {
                        'port': port,
                        'transport': 'tcp',  # All the filtered services use TCP
                        'timestamp': host['data'][-1]['timestamp'],  # Use the timestamp of the oldest banner
                        'placeholder': True,  # Don't store this banner when the file is saved
                    }
                    host['data'].append(banner)
        
            output += 'Ports:\n'
            for banner in sorted(host['data'], key=lambda k: k['port']):
                product = ''
                version = ''
                if 'product' in banner and banner['product']:
                    product = banner['product']
                if 'version' in banner and banner['version']:
                    version = '({})'.format(banner['version'])
        
                output += '{:>7d}'.format(banner['port'])
                if 'transport' in banner:
                    output += '/'
                    output += '{} '.format(banner['transport'])
                output += '{} {}\n'.format(product, version)
        
                #if history:
                    # Format the timestamp to only show the year-month-day
                #    date = banner['timestamp'][:10]
                #    output += '\t\t({})'.format(date)
                output += ''
        
                if 'ssl' not in banner and banner['data']:
                    tmp = banner['data']
                    output += '{}\n'.format(textwrap.indent(banner['data'], '\t'))
        
                # Show optional ssl info
                if 'ssl' in banner:
                    if 'versions' in banner['ssl'] and banner['ssl']['versions']:
                        output += '\t|-- SSL Versions: {}\n'.format(', '.join([item for item in sorted(banner['ssl']['versions']) if not version.startswith('-')]))
                    if 'subject' in banner['ssl']['cert']:
                        output += '\t|-- Subject: {}\n'.format(', '.join("{}={}".format(key,value) for key,value in banner['ssl']['cert']['subject'].items()))
                    if 'dhparams' in banner['ssl'] and banner['ssl']['dhparams']:
                        output += '\t|-- Diffie-Hellman Parameters:\n'
                        output += '\t\t{:15s}{}\n\t\t{:15s}{}\n'.format('Bits:', banner['ssl']['dhparams']['bits'], 'Generator:', banner['ssl']['dhparams']['generator'])
                        if 'fingerprint' in banner['ssl']['dhparams']:
                            output += '\t\t{:15s}{}\n'.format('Fingerprint:', banner['ssl']['dhparams']['fingerprint'])
                    if 'subjectAltName' in str(banner['ssl']['cert']['extensions']):
                         cert = x509.load_pem_x509_certificate(banner['ssl']['chain'][0].encode('utf-8'), default_backend())
                         ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                         output += '\t|-- Subject alt names: {}\n'.format(', '.join([str(item.value) for item in ext.value]))
        
            output = re.sub(r"\x00|\x01|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0b|\x0c|\x0e|\x0f|\x10|\x11|\x12|\x13|\x14|\x15|\x16|\x17|\x18|\x19|\x1a|\x1b|\x1c|\x1d|\x1e|\x7f", lambda m: "\\" + hex(bytearray(m.group(0).encode("utf-8"))[0]) if m.group(0) else '0',output)
            return "<pre><code>"+output+"</code></pre>"
          except Exception as aiEx:
            await crashLog(event,aiEx)
            return f"<pre><code>Error: {aiEx}</code></pre>"
        else:
            return "Please set up an API key to use this command."

ShodanCmd = ShodanAPI()
