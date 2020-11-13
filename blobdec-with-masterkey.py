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
    import dpapick3.blob as blob
    import dpapick3.masterkey as masterkey
    import dpapick3.registry as registry
except ImportError:
    raise ImportError('[-] Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not options.masterkey:
        sys.exit('[-] You must provide masterkey!')
    if not args or not len(args) == 1:
        sys.exit('[-] You must provide an argument.')


if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] BLOB\n\n'
        'It tries to decrypt a user|system DPAPI encrypted BLOB.'
        'use mksdec.py or mkudec.py to decrypt the masterkey')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='HEX', dest='masterkey')
    parser.add_option('--entropy_hex', metavar='HIVE', dest='entropy_hex')

    (options, args) = parser.parse_args()

    check_parameters(options, args)
    
    blob = blob.DPAPIBlob(open(args[0], 'rb').read())

    entropy = None
    if options.entropy_hex: entropy = bytes.fromhex(options.entropy_hex)
    try: raw_masterkey = bytes.fromhex(options.masterkey)
    except: sys.exit('[-] Error: masterkey must be HEX values only')
        
    blob.decrypt(raw_masterkey, entropy=entropy)
    if blob.decrypted:
        print('[+] Blob Decrypted, HEX and TEXT following...')
        print(('-' * 79))
        print((blob.cleartext.hex()))
        print(('-' * 79))
        print((blob.cleartext))
        print(('-' * 79))
    else:
        print('[-] Unable to decrypt blob')
    