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
"""Decrypt Windows Credential files."""

import construct, optparse, os, sys, re

try:
    import vaultstruct
except ImportError:
    raise ImportError('Missing vaultstruct.py, download it from dpapilab-ng.')

try:
    from dpapick3 import blob, registry, masterkey
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or len(args) != 1:
        sys.exit('[-] You must provide a vaults directory.')
    elif not os.path.isdir(args[0]):
        sys.exit('[-] You must provide a vaults directory.')
    if not options.masterkeydir and not options.sysmkdir:
        sys.exit('[-] Cannot decrypt anything without master keys.')
    if options.system and options.security:
        return
    if not options.sid:
        try:
            options.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", options.masterkeydir)[0]
            print('[+] Detected SID: ' + options.sid)
        except:
            sys.exit('[-] You must provide the user\'s SID textual string.')
    if not options.password and not options.pwdhash:
        sys.exit(
            'You must provide the user password or the user password hash. '
            'The user password hash is the SHA1(UTF_LE(password)), and must '
            'be provided as the hex textual string.'
            'If there\'s no password, use pwdhash "da39a3ee5e6b4b0d3255bfef95601890afd80709"')

def decrypt_blob(mkp, blob):
    """Helper to decrypt blobs."""
    mks = mkp.getMasterKeys(blob.mkguid.encode())
    if mks:
        for mk in mks:
            if mk.decrypted:
                blob.decrypt(mk.get_key())
                if blob.decrypted:
                    break
    else:
        return None, 1
    if blob.decrypted:
        return blob.cleartext, 0
    return None, 2


def decrypt_credential_block(mkp, credential_block):
    """Helper to decrypt credential block."""
    sblob_raw = b''.join(
            b.raw_data for b in credential_block.CREDENTIAL_DEC_BLOCK_ENC)

    sblob = blob.DPAPIBlob(sblob_raw)

    return decrypt_blob(mkp, sblob)


def helper_dec_err(res):
    if res == 1:
        print('[-] MasterKey not found for blob.', file=sys.stderr)
    elif res == 2:
        print('[-] Unable to decrypt blob.', file=sys.stderr)
    else:
        print('[-] Decryption error.', file=sys.stderr)


if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] credential1 credential2 ...\n\n'
        'It tries to decrypt user/system credential files.\n'
        '%appdata%\\Microsoft\\Credentials\\* or \n'
        '%localappdata%\\Microsoft\\Credentials\\* or \n'
        '\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\* or \n'
        '\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Credentials\\*\n'
        'Provide system MK data for system credentials:\n'
        '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\n'
        'or user MK data for user credentials:\n'
        '%appdata%\\Microsoft\\Protect\\<User-SID>')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash')
    parser.add_option('--sysmkdir', metavar='DIRECTORY', dest='sysmkdir')
    parser.add_option('--system', metavar='HIVE', dest='system')
    parser.add_option('--security', metavar='HIVE', dest='security')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    umkp = None
    if options.masterkeydir:
        umkp = masterkey.MasterKeyPool()
        umkp.loadDirectory(options.masterkeydir)
        if options.credhist:
            umkp.addCredhistFile(options.sid, options.credhist)
        if options.password:
            umkp.try_credential(options.sid, options.password)
        elif options.pwdhash:
            umkp.try_credential_hash(
                options.sid, bytes.fromhex(options.pwdhash))

    smkp = None
    if options.sysmkdir and options.system and options.security:
        reg = registry.Regedit()
        secrets = reg.get_lsa_secrets(options.security, options.system)
        dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']
        smkp = masterkey.MasterKeyPool()
        smkp.loadDirectory(options.sysmkdir)
        smkp.addSystemCredential(dpapi_system)
        smkp.try_credential_hash(None, None)
        can_decrypt_sys_blob = True

    for cred_path in args:
        for cred_file in os.listdir(cred_path.replace('*','')):
            with open(os.path.join(cred_path.replace('*',''),cred_file), 'rb') as fin:
                print(('-'*79))
                print(('-'*5)+' File: '+cred_file+' '+('-'*5))
                
                enc_cred = vaultstruct.CREDENTIAL_FILE.parse(fin.read())
    
                cred_blob = blob.DPAPIBlob(enc_cred.data.raw)
                print('[+] MK GUID: {}'.format(cred_blob.mkguid))
                #print(cred_blob)
    
                if umkp:
                    dec_cred, res_err = decrypt_blob(umkp, cred_blob)
                elif smkp:
                    dec_cred, res_err = decrypt_blob(smkp, cred_blob)
                else:
                    sys.exit('No MasterKey pools available!')
    
                if not dec_cred:
                    helper_dec_err(res_err)
                    continue                 
    
                try: cred_dec = vaultstruct.CREDENTIAL_DECRYPTED.parse(dec_cred)
                except: break
                print(cred_dec)
                if cred_dec.header.unk_type == 3:
                    print(cred_dec.header)
                    print(cred_dec.main)
    
                elif cred_dec.header.unk_type == 2:
                    if smkp:
                        try: cred_block_dec = decrypt_credential_block(smkp, cred_dec)
                        except: continue
                        if not cred_block_dec:
                            print(cred_dec)
                            print('Unable to decrypt CRED BLOCK.', file=sys.stderr)
                        else:
                            print(cred_dec.header)
                            print(cred_dec.main)
                            print(('-'*40))
                            print(cred_block_dec)
                    else:
                        print(cred_dec)
                        print('[-] Missing system MasterKeys info!', file=sys.stderr)
                        print('[-] Unable to decrypt further blocks!', file=sys.stderr)
    
                else:
                    print('[-] Unknown CREDENTIAL type, please report.', file=sys.stderr)
                    print(cred_dec)

        #print(('-'*79))
