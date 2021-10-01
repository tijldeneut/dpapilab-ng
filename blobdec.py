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
""" Windows DPAPI BLOB decryption utility."""

import optparse, os, sys

try:
    from dpapick3 import blob, masterkey, registry
except ImportError:
    raise ImportError('[-] Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not options.masterkeydir:
        sys.exit('You must provide a masterkeys directory!')
    if not options.sid:
        try:
            options.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", args[0])[0]
            print('[+] Detected SID: ' + options.sid)
        except:
            pass
    if options.sid:
        if not options.password and not options.pwdhash:
            sys.exit('You must provide the user password or password hash!')
    else:
        if not options.security or not options.system:
            sys.exit('You must provide SYSTEM and SECURITY hives.')
    if not args or not len(args) == 1:
        sys.exit('You must provide an argument.')


if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] BLOB\n\n'
        'It tries to decrypt a user|system DPAPI encrypted BLOB.\n'
        'User blob needs sid and password at least.\n'
        'System blob needs system and security at least.')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--system', metavar='HIVE', dest='system')
    parser.add_option('--security', metavar='HIVE', dest='security')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash', help='Example for empth hash: da39a3ee5e6b4b0d3255bfef95601890afd80709')
    parser.add_option('--entropy_hex', metavar='HIVE', dest='entropy_hex')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(options.masterkeydir)

    if options.sid:
        if options.credhist:
            mkp.addCredhistFile(options.sid, options.credhist)
        if options.password:
            mkp.try_credential(options.sid, options.password)
        elif options.pwdhash:
            mkp.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))
    else:
        reg = registry.Regedit()
        secrets = reg.get_lsa_secrets(options.security, options.system)
        dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']

        mkp.addSystemCredential(dpapi_system)
        mkp.try_credential_hash(None, None)

    blob = blob.DPAPIBlob(open(args[0], 'rb').read())

    mks = mkp.getMasterKeys(blob.mkguid.encode())

    entropy = None
    if options.entropy_hex:
        entropy = bytes.fromhex(options.entropy_hex)

    if len(mks) == 0:
        sys.exit('[-] Unable to find MK for blob %s' % blob.mkguid)

    for mk in mks:
        if mk.decrypted:
            blob.decrypt(mk.get_key(), entropy=entropy)
            if blob.decrypted:
                print('Blob Decrypted, HEX and TEXT following...')
                print(('-' * 79))
                print((blob.cleartext.hex()))
                print(('-' * 79))
                print((blob.cleartext))
                print(('-' * 79))
                print((blob.cleartext.decode('UTF-16LE',errors='ignore')))
                print(('-' * 79))
            else:
                print('[-] Unable to decrypt blob')
        else:
            print('[-] Unable to decrypt master key')
