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
"""DECRYPTING VAULT FILES (VCRD) """

import optparse, os, sys, re
from Crypto.Cipher import AES

try:
    from dpapick3 import blob, masterkey, registry
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

import vaultstruct, vaultschema

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or len(args) != 1:
        sys.exit('[-] You must provide a vaults directory.')
    elif not os.path.isdir(args[0]):
        sys.exit('[-] You must provide a vaults directory.')
    if not options.masterkeydir:
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
            'be provided as the hex textual string.')


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
        print('MasterKey not found for blob.', file=sys.stderr)

    if blob.decrypted: 
        return blob.cleartext
    return None

    
def decrypt_vault_attribute(vault_attr, key_aes128, key_aes256):
    """Helper to decrypt VAULT attributes."""
    if not vault_attr.size:
        return '', False

    if vault_attr.has_iv:
        cipher = AES.new(key_aes256, AES.MODE_CBC, vault_attr.iv)
        is_attribute_ex = True
    else:
        cipher = AES.new(key_aes128, AES.MODE_CBC)
        is_attribute_ex = False

    return cipher.decrypt(vault_attr.data), is_attribute_ex


def get_vault_schema(guid, base_dir, default_schema):
    '''Helper to get the Vault schema to apply on decoded data.'''
    vault_schema = default_schema
    schema_file_path = os.path.join(base_dir, guid + '.vsch')
    try:
        with open(schema_file_path, 'rb') as fschema:
            vsch = vaultschema.VAULT_VSCH.parse(fschema.read())
            vault_schema = vaultschema.vault_schemas.get(
                vsch.schema_name.data,
                vaultschema.VAULT_SCHEMA_GENERIC)
    except IOError:
        pass
    return vault_schema


if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] Vault Directory\n\n'
        'It tries to decrypt Vault VCRD files.\n'
        'E.g.: Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault\\<GUID>\n'
        'or  : %ProgramData%\\Microsoft\\Vault\\<GUID>\n'
        'or  : %localappdata%\\Microsoft\\Vault\\<GUID>\n'
        'Can work with user MK *or* system MKs')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash')
    parser.add_option('--system', metavar='HIVE', dest='system')
    parser.add_option('--security', metavar='HIVE', dest='security')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(options.masterkeydir)

    if options.security and options.system:
        reg = registry.Regedit()
        secrets = reg.get_lsa_secrets(options.security, options.system)
        dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']
        mkp.addSystemCredential(dpapi_system)
        mkp.try_credential_hash(None, None)
    else:
        if options.credhist:
            mkp.addCredhistFile(options.sid, options.credhist)
        if options.password:
            mkp.try_credential(options.sid, options.password)
        elif options.pwdhash:
            mkp.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))

    vaults_dir = args[0]
    vpol_filename = os.path.join(vaults_dir, 'Policy.vpol')

    with open(vpol_filename, 'rb') as fin:
        vpol = vaultstruct.VAULT_POL.parse(fin.read())
    
    vpol_blob = blob.DPAPIBlob(vpol.vpol_store.blob_store.raw)

    vpol_decrypted = decrypt_blob(mkp, vpol_blob)
    if not vpol_decrypted:
        sys.exit('Unable to decrypt blob.')

    vpol_keys = vaultstruct.VAULT_POL_KEYS.parse(vpol_decrypted)

    key_aes128 = vpol_keys.vpol_key1.bcrypt_blob.key
    key_aes256 = vpol_keys.vpol_key2.bcrypt_blob.key

    for file in os.listdir(vaults_dir):
        if file.lower().endswith('.vcrd'):
            filepath = os.path.join(vaults_dir, file)
            print('-' * 79)
            print('Working on: %s\n' % file)

            attributes_data = {}
            
            with open(filepath, 'rb') as fin:
                vcrd = vaultstruct.VAULT_VCRD.parse(fin.read())

                current_vault_schema = get_vault_schema(
                    vcrd.schema_guid,
                    vaults_dir,
                    vaultschema.VAULT_SCHEMA_GENERIC)
                
                for attribute in vcrd.attributes:
                    
                    decrypted, is_attribute_ex = decrypt_vault_attribute(
                        attribute.VAULT_ATTRIBUTE, key_aes128, key_aes256)

                    if is_attribute_ex:
                        schema = current_vault_schema
                    else:
                        schema = vaultschema.VAULT_SCHEMA_SIMPLE
                        
                    if not decrypted: decrypted = b''

                    attributes_data[attribute.VAULT_ATTRIBUTE.id] = {
                        'data': decrypted,
                        'schema': schema
                    }

                attributes_data[0xDEAD0000 + vcrd.extra_entry.id] = {
                    'data': vcrd.extra_entry.data,
                    'schema': vaultschema.VAULT_SCHEMA_SIMPLE
                }
            
            for k,v in attributes_data.items():
                ## v['schema'].name.lower() could be "vault_schema_generic"
                print('Attribute: {0:x} ({1:s})'.format(k, v['schema'].name.lower()))
                dataout = v['schema'].parse(v['data'])
                '''
                print('o'*50)
                print(dataout)
                print('o'*50)
                if v['schema'].name.lower() == 'vault_schema_generic':
                    for line in dataout:
                        print('####')
                        print(type(line))
                '''
                print(dataout)
