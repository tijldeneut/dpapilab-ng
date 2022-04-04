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
""" Windows DPAPI system's MasterKeys decryption utility."""

import hashlib, optparse, os, sys

try:
    from dpapick3 import masterkey, registry
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not options.security or not options.system:
        sys.exit('You must provide SYSTEM and SECURITY hives.')
    if not args:
        sys.exit('You must provide at least one MasterKey file.')

def parseGUID(bData):
    def reverseByte(bByteInput):
        sReversed = ''
        sHexInput = bByteInput.hex()
        for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
        return bytes.fromhex(sReversed)
    return reverseByte(bData[:4]).hex() + '-' + reverseByte(bData[4:6]).hex() + '-' + reverseByte(bData[6:8]).hex() + '-' + bData[8:10].hex() + '-' + bData[10:].hex()

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] MKfile1 MKfile2 etc.\n\n'
        'It tries to unlock (decrypt) *system* MasterKey files provided.\n'
        r' Default System MK locations: Windows\System32\Microsoft\Protect\S-1-5-18\{User}')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--system', metavar='HIVE', default=os.path.join('Windows','System32','config','SYSTEM'), help=r'SYSTEM file; default: Windows\System32\config\SYSTEM')
    parser.add_option('--security', metavar='HIVE', default=os.path.join('Windows','System32','config','SECURITY'), help=r'SECURITY file; default: Windows\System32\config\SECURITY')

    (options, args) = parser.parse_args()
    
    check_parameters(options, args)

    reg = registry.Regedit()
    secrets = reg.get_lsa_secrets(options.security, options.system)
    dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']

    mkp = masterkey.MasterKeyPool()
    mkp.addSystemCredential(dpapi_system)

    for arg in args:
        arg = arg.replace('*','')
        if os.path.isfile(arg):
            with open(arg,'rb') as f:
                if arg == 'Preferred': print('[+] Preferred Key is ' + parseGUID(f.read())[:36])
                try: mkp.addMasterKey(f.read())
                except: pass
        else:
            for file in os.listdir(arg):
                filepath = os.path.join(arg, file)
                if not os.path.isfile(filepath): break
                with open(filepath, 'rb') as f:
                    if file == 'Preferred': print('[+] Preferred Key is ' + parseGUID(f.read())[:36])
                    try: mkp.addMasterKey(f.read())
                    except: pass

    mkp.try_credential_hash(None, None)

    for mkl in list(mkp.keys.values()):
        for mk in mkl:
            print('')
            print(('[!] Working on MK GUID %s\n-------------' % mk.guid.decode()))
            if mk.decrypted:
                print('[+] MASTER KEY UNLOCKED!')
                mkey = mk.get_key()
                print(('[+] KEY: %s' % mkey.hex()))
                print(('[+] SHA1: %s' % hashlib.sha1(mkey).digest().hex()))
            else:
                print(('[-] MK guid: %s' % mk.guid))
                print('[-] UNABLE to UNLOCK master key')
            print('')
