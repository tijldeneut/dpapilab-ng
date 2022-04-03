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
""" Windows KeePass ProtectedUserKey DPAPI BLOB decryption utility."""

import optparse, sys, re

try:
    from dpapick3 import blob, masterkey
except ImportError:
    raise ImportError('[-] Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not options.masterkeydir:
        sys.exit('You must provide a masterkeys directory!')
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
    if not args or not len(args) == 1:
        sys.exit('You must provide an argument.')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] ProtectUserKeyBlob\n\n'
        'It tries to decrypt a KeePass user DPAPI encrypted BLOB.\n'
        'Commonly found in\n'
        'C:\\Users\\User\\AppData\\Roaming\\KeePass\\ProtectedUserKey.bin\n'
        'Needs user MasterKey and either SID+password/hash or Domain PVK')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash', help='Example for empth hash: da39a3ee5e6b4b0d3255bfef95601890afd80709')
    parser.add_option('--pvk', '-k', help='Optional: Depending on MK; domain RSA PVK keyfile')
    parser.add_option('--entropy_hex', metavar='HIVE', dest='entropy', default='DE135B5F18A34670B2572429698898E6', help='Default KeePass Entropy: DE135B5F18A34670B2572429698898E6')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    oMKP = masterkey.MasterKeyPool()
    oMKP.loadDirectory(options.masterkeydir)

    if options.credhist: oMKP.addCredhistFile(options.sid, options.credhist)
    if options.password: oMKP.try_credential(options.sid, options.password)
    elif options.pwdhash: oMKP.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))
    if options.pvk: oMKP.try_domain(options.pvk)

    blob = blob.DPAPIBlob(open(args[0], 'rb').read())

    mks = oMKP.getMasterKeys(blob.mkguid.encode())

    bEntropy = None
    if options.entropy:
        bEntropy = bytes.fromhex(options.entropy)

    if len(mks) == 0:
        sys.exit('[-] Unable to find MK for blob %s' % blob.mkguid)

    for mk in mks:
        if mk.decrypted:
            blob.decrypt(mk.get_key(), entropy = bEntropy)
            if blob.decrypted:
                print('Blob Decrypted, HEX and TEXT following...')
                print(('-' * 79))
                print((blob.cleartext.hex()))
                print(('-' * 79))
                print('[+] Now if the KDBX database is only encrypted by "Windows Account", this should work:\n'
                      '     CQDPAPIKeePassDBDecryptor.exe /k ' + blob.cleartext.hex() + ' /f <file>.kdbx\n'
                      '     Open the new kdbx file with password "cqure".')
            else:
                print('[-] Unable to decrypt blob')
        else:
            print('[-] Unable to decrypt master key')
