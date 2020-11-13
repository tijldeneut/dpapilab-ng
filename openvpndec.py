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
""" Windows OpenVPN password offline decryptor."""

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
        sys.exit('[-] You must provide the ntuser.dat file (or reg save hkcu ntuser.dat).')
    if not options.sid:
        sys.exit('[-] You must provide the user SID to decrypt password.') 
    if not options.masterkeydir:
        sys.exit('[-] You must provide the user DPAPI folder, see <usage>.')
    if not options.password and not options.pwdhash:
        sys.exit('[-] You must provide the user password or password hash.')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] NTUSER\n\n'
        'It decrypts Windows OpenVPN password stored in '
        'registry HKCU, which is stored in NTUSER.dat\n'
        'You must provide the file NTUSER.dat, corresponding user SID and password or hash,\n'
        'and the user DPAPI MasterKeys, stored in '
        '\\<User>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>'
        )

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash')
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
    with open(args[0], 'rb') as f:
        r = registry.Registry.Registry(f)
        arrProfiles = r.open('Software\\OpenVPN-GUI\\configs')
        if len(arrProfiles.subkeys()) <= 0:
            exit('[-] Error, no profiles found in ntuser.dat')
        for key in arrProfiles.subkeys():
            print(('[!] Attempting to decrypt: ' + key.name()))
            try: entropy = key.value('entropy').value()
            except: entropy = None
            try: vpnblob = blob.DPAPIBlob(key.value('key-data').value())
            except: vpnblob = blob.DPAPIBlob(key.value('auth-data').value())
            mks = mkp.getMasterKeys(vpnblob.mkguid.encode())
            for mk in mks:
                if mk.decrypted:
                    ## Entropy ends with a nullbyte
                    vpnblob.decrypt(mk.get_key(), entropy = entropy.rstrip(b'\x00'))
                    if vpnblob.decrypted: 
                        ## Cleartext is a unicode string
                        print(('[+] OpenVPN profile "{}" has password "{}"'.format(key.name(), vpnblob.cleartext.decode('utf16').rstrip('\x00'))))