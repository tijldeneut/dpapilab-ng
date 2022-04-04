#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
# Copyright 2020, Tijl "Photubias" Deneut <tijl.deneut@howest.be>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""" Windows system Wi-Fi password offline and online decryptor."""

import optparse, os, re, sys

try:
    from dpapick3 import blob, masterkey, registry
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if args: sys.exit('Error: No arguments required, see <usage>')
    if not options.security or not options.system: sys.exit('You must provide SYSTEM and SECURITY hives to decrypt username.')
    if not options.systemmasterkeydir: sys.exit('You must provide the system DPAPI folder, see <usage>.')
    if not options.ntuser: sys.exit('You must provide the ntuser.dat file (or reg save hkcu ntuser.dat).')
    if not options.usermasterkeydir: sys.exit('You must provide the user DPAPI folder, see <usage>.')
    if not options.sid:
        try:
            options.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", options.usermasterkeydir)[0]
            print('[+] Autodetected SID: ' + options.sid)
        except:
            sys.exit('You must provide the user\'s SID textual string.')
    if not options.password and not options.pwdhash: 
        print('[!] No password provided, assuming user has no password.')
        options.pwdhash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        #sys.exit('You must provide the user password or password hash.')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] *noargs*\n\n'
        'It decrypts Windows Wi-Fi Enterprise password stored in registry HKCU, which is stored in NTUSER.dat\n'
        'wdir is needed for getting the profile name:\n'
        '\\ProgramData\\Microsoft\\WlanSvc\\Profiles files.\n'
        'You must provide such directory, NTUSER.dat, SYSTEM and SECURITY hives and,\n'
        'the system DPAPI MasterKeys, stored in\n'
        '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\n'
        'but also the user DPAPI MasterKeys, stored in\n'
        '\\<User>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>'
        )

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--systemmasterkey', metavar='FOLDER',default=os.path.join('Windows','System32','Microsoft','Protect','S-1-5-18','User') , dest='systemmasterkeydir', help=r'System Masterkey folder; default: Windows\System32\Microsoft\Protect\S-1-5-18\User')
    parser.add_option('--system', metavar='HIVE', default=os.path.join('Windows','System32','config','SYSTEM'), help=r'SYSTEM file; default: Windows\System32\config\SYSTEM')
    parser.add_option('--security', metavar='HIVE', default=os.path.join('Windows','System32','config','SECURITY'), help=r'SECURITY file; default: Windows\System32\config\SECURITY')
    parser.add_option('--wdir', metavar='WIFIDIR', dest='wifi_dir', default=os.path.join('ProgramData','Microsoft','Wlansvc'), help=r'WiFi folder; default ProgramData\Microsoft\Wlansvc')
    parser.add_option('--ntuser', metavar='NTUSER', dest='ntuser')
    parser.add_option('--usermasterkey', metavar='DIRECTORY', dest='usermasterkeydir')
    parser.add_option('--sid', metavar='SID', dest='sid', help=r'Carved from the User Masterkey folder, if possible')
    parser.add_option('--password', metavar='PASSWORD', dest='password', help='Optional: Will use empty password when not provided')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    reg = registry.Regedit()
    secrets = reg.get_lsa_secrets(options.security, options.system)
    dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']
    #print('[+] SYSTEM DPAPI key: {}'.format(dpapi_system.hex()))

    mkp1 = masterkey.MasterKeyPool()
    mkp1.loadDirectory(options.systemmasterkeydir)
    mkp1.addSystemCredential(dpapi_system)
    mkp1.try_credential_hash(None, None)

    mkp2 = masterkey.MasterKeyPool()
    mkp2.loadDirectory(options.usermasterkeydir)
    if options.credhist:
        mkp2.addCredhistFile(options.sid, options.credhist)
    if options.password:
        mkp2.try_credential(options.sid, options.password)
    if options.pwdhash:
        mkp2.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))

    for root, _, files in os.walk(options.wifi_dir):
        for file in files:
            filepath = os.path.join(root, file)
            with open(filepath, 'r') as f:
                file_data = f.read().replace('\x0a', '').replace('\x0d', '')
                wifi_name = re.search('<name>([^<]+)</name>', file_data)
                wifi_name = wifi_name.group(1)
                if not re.search('<EAPConfig>', file_data): 
                    continue
                with open(options.ntuser, 'rb') as f:
                    r = registry.Registry.Registry(f)
                    try: hexdata1 = r.open('Software\\Microsoft\\Wlansvc\\UserData\\Profiles\\' + file[:38]).value('MSMUserData').value()
                    except: sys.exit('[-] Error: No Wi-Fi data in NTUSER, wrong user?')
                    ## DPAPI Blob containing username, possibly domain and another DPAPI blob with password
                    wblob1 = blob.DPAPIBlob(hexdata1)
                    wifi_username = '<not decrypted>'
                    wifi_domain = '<none>'
                    wifi_pwd = '<not decrypted>'
                    mks1 = mkp1.getMasterKeys(wblob1.mkguid.encode())
                    for mk1 in mks1:
                        if mk1.decrypted:
                            wblob1.decrypt(mk1.get_key())
                            if wblob1.decrypted:
                                hexdata2 = wblob1.cleartext.hex()
                                wifi_username = bytes.fromhex(hexdata2.split('0400000002000000')[1].split('00')[0]).decode(errors='ignore')
                                try: wifi_domain = bytes.fromhex(hexdata2.split('0400000002000000')[1].split('00')[1]).decode(errors='ignore')
                                except: pass
                                wblob2 = blob.DPAPIBlob(bytes.fromhex('01000000d08c9ddf01' + hexdata2.split('01000000d08c9ddf01')[1]))
                                mks2 = mkp2.getMasterKeys(wblob2.mkguid.encode())
                                for mk2 in mks2:
                                    if mk2.decrypted:
                                        wblob2.decrypt(mk2.get_key())
                                        if wblob2.decrypted:
                                            wifi_pwd = wblob2.cleartext.rstrip(b'\x00').decode(errors='ignore')
                print(('[+] Wi-Fi: {}\n    Username: {}\n    Domain: {}\n    Password: {}'.format(wifi_name, wifi_username, wifi_domain, wifi_pwd)))
