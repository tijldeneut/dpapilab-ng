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
"""Microsoft Remote Desktop Manager RDG password offline decryptor."""

import optparse, os, re, sys, base64
from lxml import objectify # pip3 install lxml

try:
    from dpapick3 import blob, masterkey
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or not len(args) == 1:
        sys.exit('[-] You must provide the RDG file.')
    if not options.masterkeydir:
        sys.exit('[-] You must provide the user DPAPI folder, see <usage>.')
    if not options.sid:
        try:
            options.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", options.masterkeydir)[0]
            print('[+] Detected SID: ' + options.sid)
        except:
            sys.exit('[-] You must provide the user\'s SID textual string.')
    if not options.password and not options.pwdhash and not options.pvk:
        print('[!] No password provided, assuming user has no password.')
        options.pwdhash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        #options.pwdhash = '31d6cfe0d16ae931b73c59d7e0c089c0' ## NT hash sometimes also works

def decryptCred(oCred, oMKP):
    sProfName = oCred.profileName
    sUser = oCred.userName
    oBlob = blob.DPAPIBlob(base64.b64decode(str(oCred.password)))
    sDomain = oCred.domain
    lstMKs = oMKP.getMasterKeys(oBlob.mkguid.encode())
    if len(lstMKs) == 0: print('[-] Unable to find MK for blob %s' % oBlob.mkguid)
    for oMK in lstMKs:
        if oMK.decrypted: oBlob.decrypt(oMK.get_key())
    if oBlob.decrypted: sClearPass = oBlob.cleartext
    else: sClearPass = None
    return (sProfName, sUser, sDomain, sClearPass.decode('UTF-16LE'))

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] RemoteConnections.rdg\n\n'
        'It decrypts Microsoft RDM passwords stored in the RDG file\n'
        'You must provide this (XML) file, corresponding user SID and password or hash,\n'
        'and the user DPAPI MasterKeys, stored in '
        r'\<User>\AppData\Roaming\Microsoft\Protect\<SID>'
        )

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash', help='Example for empth hash: da39a3ee5e6b4b0d3255bfef95601890afd80709')
    parser.add_option('--pvk', '-k', help='Optional: Depending on MK; domain RSA PVK keyfile')

    (options, args) = parser.parse_args()

    check_parameters(options, args)
    
    oMKP = masterkey.MasterKeyPool()
    oMKP.loadDirectory(options.masterkeydir)

    if options.credhist: oMKP.addCredhistFile(options.sid, options.credhist)
    if options.password: oMKP.try_credential(options.sid, options.password)
    elif options.pwdhash: oMKP.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))
    if options.pvk: oMKP.try_domain(options.pvk)

    oTree = objectify.fromstring(open(args[0],'rb').read())
    
    lstCreds = []
    for oLogonCreds in oTree.file:
        try: lstCreds.append(decryptCred(oLogonCreds.logonCredentials, oMKP))
        except: pass
    for oProfs in oTree.file.credentialsProfiles:
        try: 
            for oCred in oProfs.credentialsProfile: lstCreds.append(decryptCred(oCred, oMKP))
        except: pass
    
    iDecrypted = 0
    for lstCred in lstCreds: # sProfName, sUser, sDomain, sClearPass
        print('[+] Profile:  {}'.format(lstCred[0]))
        print('    Username: {}'.format(lstCred[1]))
        print('    Domain:   {}'.format(lstCred[2]))
        if lstCred[3]:
            iDecrypted += 1    
            print('    Password: {}'.format(lstCred[3]))
    print(('-' * 79))
    print('[+] Decrypted {} out of {} credentials'.format(iDecrypted, len(lstCreds)))
    