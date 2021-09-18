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
""" Windows DPAPI CREDHIST decryption utility."""

import optparse, os, sys

try:
    import dpapick3.credhist as credhist
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')


def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not options.password and not options.pwdhash:
        print('[!] Without password or hash, only the structure will be shown')
    if not args or not len(args) == 1:
        sys.exit('[-] You must provide an argument.')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] CREDHIST\n\n'
        'It tries to decrypt a user CREDHIST file.\n'
        'AppData\\Roaming\\Microsoft\\Protect\\CREDHIST\n'
        'Needs either the current user SHA1 hash or cleartext password.')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash')

    (options, args) = parser.parse_args()

    check_parameters(options, args)
    
    cred = credhist.CredHistFile(open(args[0], 'rb').read())
    if len(cred.entries_list) == 0: sys.exit('[-] No entries in this CREDHIST file')
    if options.pwdhash:  cred.decryptWithHash(bytes.fromhex(options.pwdhash))
    elif options.password: cred.decryptWithPassword(options.password)
    for s in cred.entries_list:
        if s.ntlm: print('[+] CREDHIST decrypted')
    print(cred)
