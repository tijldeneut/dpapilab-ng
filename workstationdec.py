#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
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
""" VMware Workstation password (offline) decryptor."""

from ntpath import join
import optparse, os, sys, re
import base64, urllib.parse, hashlib, hmac
from Crypto.Cipher import AES

bStaticKey = bytes.fromhex('a0142a55c74d1f63715f13f53b69d3ac')
sStaticPassword = '{23F781A1-4126-4bba-BC8A-9DD33D0E2362}'

try:
    from dpapick3 import blob, masterkey
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or not len(args) == 1:
        sys.exit('[-] You must provide the VMware folder containing at least 2 files:\npreferences-private.ini and ace.dat.')
    if not options.masterkeydir:
        sys.exit('[-] You must provide the user DPAPI folder, see <usage>.')
    if not options.sid:
        try: options.sid = re.findall(r"S-1-[0-5]-\d{2}-\d+-\d+-\d+-\d+", options.masterkeydir)[0]
        except: sys.exit('[-] You must provide the user SID to decrypt password.')
    if not options.password and not options.pwdhash:
        sys.exit('[-] You must provide the user password or password hash.')

def parseHosts(bData):
    lstCreds = []
    sHost = sUser = sPass = ''
    for bLine in bData.split(b'\n'):
        if '.hostID' in bLine.decode(): sHost = bLine.split(b' = ')[1].decode().replace('"','')
        elif '.username' in bLine.decode(): sUser = bLine.split(b' = ')[1].decode().replace('"','')
        elif '.password' in bLine.decode(): sPass = bLine.split(b' = ')[1].decode().replace('"','')
        if sHost and sUser and sPass:
            lstCreds.append((sHost,sUser,sPass))
            sHost = sUser = sPass = ''
    return lstCreds

def parseAce(sFilepath):
    sData = ''
    try: 
        with open(sFilepath,'r') as file:
            sLine = file.readline()
            while sLine:
                if sLine.startswith('data'): 
                    sData = sLine.split(' = ')[1].strip().replace('"','')
                    break
                sLine = file.readline()
    except: exit('[-] Error: file ' + sFilepath + ' not found or corrupt.')
    finally: file.close()
    bData = base64.b64decode(sData)
    return bData

def parsePreferences(sFilepath, mkp):
    # userKey (DPAPI blob with AES key, 32 bytes), keySafe (x bytes), data (x bytes)
    sUserKey = sKeySafe = sData = ''
    try: 
        with open(sFilepath,'r') as file:
            sLine = file.readline()
            while sLine:
                if sLine.startswith('encryption.userKey'): sUserKey = sLine.split(' = ')[1].strip().replace('"','')
                elif sLine.startswith('encryption.keySafe'): sKeySafe = sLine.split(' = ')[1].strip().replace('"','')
                elif sLine.startswith('encryption.data'): sData = sLine.split(' = ')[1].strip().replace('"','')
                sLine = file.readline()
    except: exit('[-] Error: file ' + sFilepath + ' not found or corrupt.')
    finally: file.close()
    # userKey
    oBlob = blob.DPAPIBlob(base64.b64decode(sUserKey))
    mks = mkp.getMasterKeys(oBlob.mkguid.encode())
    for mk in mks:
        if mk.decrypted:
            oBlob.decrypt(mk.get_key())
            if oBlob.decrypted: 
                bUserKey = base64.b64decode(urllib.parse.unquote(oBlob.cleartext.decode()).split(':key=')[1])
    # keySafe
    bKeySafe = base64.b64decode(urllib.parse.unquote(sKeySafe.split('/')[len(sKeySafe.split('/'))-1].split(',')[2].replace(')','')))
    # data
    bData = base64.b64decode(sData)
    return (bUserKey, bKeySafe, bData)

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] VMware-folder\n\n'
        'It decrypts VMware Workstation credentials stored in\n'
        '\\<User>\\AppData\\Roaming\\VMware; files ace.dat and preferences-private.ini\n'
        'You must provide the folder with these 2 files, the corresponding user SID, password or hash,\n'
        'and the user DPAPI MasterKeys, stored in\n'
        '\\<User>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>'
        )

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash', help='Example for empth hash: da39a3ee5e6b4b0d3255bfef95601890afd80709')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')

    (options, args) = parser.parse_args()

    check_parameters(options, args)
    
    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(options.masterkeydir)
    if options.credhist:
        mkp.addCredhistFile(options.sid, options.credhist)
    if options.password:
        mkp.try_credential(options.sid, options.password)
    if options.pwdhash:
        mkp.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))
    
    (bUserKey, bKeySafe, bData) = parsePreferences(os.path.join(args[0],'preferences-private.ini'), mkp)
    bData3 = parseAce(os.path.join(args[0],'ace.dat'))

    # Step 1: decrypt keySafe with userKey
    bDataStep1 = AES.new(bUserKey, AES.MODE_CBC, bKeySafe[:16]).decrypt(bKeySafe[16:-20])
    bDataStep1 = bDataStep1.rstrip(bDataStep1[-1:]) ## strip trailing characters
    ## Optional verification: 
    bVerification1 = hmac.new(bUserKey, bDataStep1, hashlib.sha1).digest()
    if not bVerification1 == bKeySafe[-20:]: exit('[-] Error during decryption of step 1; current result:\n    ' + bDataStep1.decode(errors='ignore'))
    bKeyStep2 = base64.b64decode(urllib.parse.unquote(bDataStep1.decode().split(':key=')[1]))
    
    # Step 2: decrypt encryption.data (bData)
    bDataStep2 = AES.new(bKeyStep2, AES.MODE_CBC, bData[:16]).decrypt(bData[16:-20])
    bDataStep2 = bDataStep2.rstrip(bDataStep2[-1:])
    bVerification2 = hmac.new(bKeyStep2, bDataStep2, hashlib.sha1).digest()
    if not bVerification2 == bData[-20:]: exit('[-] Error during decryption of step 2; current result:\n    ' + bDataStep2.decode(errors='ignore'))
    print('[+] Host decryption successful:')
    print(urllib.parse.unquote(bDataStep2.strip(b'\n').decode()))
    print('-'*25)
    lstCreds = parseHosts(bDataStep2)
    
    # Step 3: decrypt ace.dat with a static AES 256 key
    bDataStep3 = AES.new(bStaticKey, AES.MODE_CBC, bData3[:16]).decrypt(bData3[16:-20])
    bDataStep3 = bDataStep3.rstrip(bDataStep3[-1:])
    bVerification3 = hmac.new(bStaticKey, bDataStep3, hashlib.sha1).digest()
    if not bVerification3 == bData3[-20:]: exit('[-] Error during decryption of step 3; current result:\n    ' + bDataStep3.decode(errors='ignore'))
    iRounds = int(bDataStep3.split(b':rounds=')[1].split(b':')[0])
    bSalt = base64.b64decode(urllib.parse.unquote(bDataStep3.split(b':salt=')[1].split(b':')[0].decode()))
    bData4 = base64.b64decode(urllib.parse.unquote(bDataStep3.split(b':data=')[1].split(b':')[0].decode()))

    # Step 4: decrypt the decrypted data from ace.dat using a derived key
    bDerivedKey = hashlib.pbkdf2_hmac('sha1', sStaticPassword.encode(), bSalt, iRounds)[:16]
    bDataStep4 = AES.new(bDerivedKey, AES.MODE_CBC, bData4[:16]).decrypt(bData4[16:-20])
    bDataStep4 = bDataStep4.rstrip(bDataStep4[-1:])
    bVerification4 = hmac.new(bDerivedKey, bDataStep4, hashlib.sha1).digest()
    if not bVerification4 == bData4[-20:]: exit('[-] Error during decryption of step 4; current result:\n    ' + bDataStep4.decode(errors='ignore'))
    bPassKey = base64.b64decode(urllib.parse.unquote(bDataStep4.split(b':key=')[1].decode()))
    
    # Step 5: final decryption of the credential(s)
    for lstCred in lstCreds:
        bPassData = base64.b64decode(lstCred[2])
        bPassword = AES.new(bPassKey, AES.MODE_CBC, bPassData[:16]).decrypt(bPassData[16:-20])
        bPassword = bPassword.rstrip(bPassword[-1:])
        bVerification5 = hmac.new(bPassKey, bPassword, hashlib.sha1).digest()
        if not bVerification5 == bPassData[-20:]: exit('[-] Error during decryption of step 5; current result:\n    ' + bPassword.decode(errors='ignore'))
        iPasslength = int(bPassword[16:][:4].hex(),16)
        sPassword = bPassword[20:20+iPasslength].decode()
        print('[+] Host:     {}\n    Username: {}\n    Password: {}'.format(lstCred[0], lstCred[1], sPassword))