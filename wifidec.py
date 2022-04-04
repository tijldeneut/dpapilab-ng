#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
# Copyright 2020, Photubias <tijl.deneut@howest.be>
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
    import dpapick3.blob as blob
    import dpapick3.masterkey as masterkey
    import dpapick3.registry as registry
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or not len(args) == 1:
        sys.exit('[-] You must provide an argument.')
    if not options.security or not options.system:
        sys.exit('You must provide SYSTEM and SECURITY hives.')
    if not options.masterkeydir:
        sys.exit('You must provide the system DPAPI folder, see <usage>.')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] WDIR\n\n'
        'It decrypts Windows WiFi password stored in '
        '\\ProgramData\\Microsoft\\Wlansvc\n'
        'You must provide such directory, SYSTEM and SECURITY hives and,\n'
        'finally, the system DPAPI MasterKeys, stored in '
        r'\Windows\System32\Microsoft\Protect\S-1-5-18\User')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--system', metavar='HIVE', default=os.path.join('Windows','System32','config','SYSTEM'), help=r'SYSTEM file; default: Windows\System32\config\SYSTEM')
    parser.add_option('--security', metavar='HIVE', default=os.path.join('Windows','System32','config','SECURITY'), help=r'SECURITY file; default: Windows\System32\config\SECURITY')
    parser.add_option('--masterkey', metavar='FOLDER', default=os.path.join('Windows','System32','Microsoft','Protect','S-1-5-18','User'), dest='masterkeydir', help=r'Masterkey folder; default: Windows\System32\Microsoft\Protect\S-1-5-18\User')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    reg = registry.Regedit()
    secrets = reg.get_lsa_secrets(options.security, options.system)
    dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']

    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(options.masterkeydir)
    mkp.addSystemCredential(dpapi_system)
    mkp.try_credential_hash(None, None)

    for root, _, files in os.walk(args[0]):
        for file in files:
            filepath = os.path.join(root, file)
            with open(filepath, 'r') as f:
                file_data = f.read().replace('\x0a', '').replace('\x0d', '')
                wifi_name = re.search('<name>([^<]+)</name>', file_data)
                wifi_name = wifi_name.group(1)
                key_material_re = re.search(
                    '<keyMaterial>([0-9A-F]+)</keyMaterial>', file_data)
                if not key_material_re:
                    if re.search('<EAPConfig>', file_data): print(('[!] The pass for EAP profile ' + wifi_name + ' (' + file  + ')'  +  ' is in the NTUSER.dat registry'))
                    else: print(('[-] No key for: ' + wifi_name))
                    continue
                key_material = bytes.fromhex(key_material_re.group(1))
                wblob = blob.DPAPIBlob(key_material)
                wifi_pwd = '<not decrypted>'
                mks = mkp.getMasterKeys(wblob.mkguid.encode())
                for mk in mks:
                    if mk.decrypted:
                        wblob.decrypt(mk.get_key())
                        if wblob.decrypted:
                            wifi_pwd = wblob.cleartext.decode(errors='ignore')
                        break
                print(('[+] SSID:     {} \n    Password: {}'.format(wifi_name, wifi_pwd)))