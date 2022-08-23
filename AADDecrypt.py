#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
# Copyright 2021, Tijl "Photubias" Deneut <tijl.deneut@howest.be>
# Copyright 2022, MisTeam <ke@misteam.ru>
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

""" Windows AAD BrokerPlugin def files decryption utility.
    …\\AppData\\Local\\Packages\\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\\LocalState\\

"""


import argparse
import re
import sys
import base64
import asn1

try: 
    from dpapick3 import probe
    from dpapick3 import blob
    from dpapick3 import masterkey
    from dpapick3 import    registry
except ImportError:
    raise ImportError('[-] Missing dpapick3, please install via pip install dpapick3.')

import binascii
from Crypto.Cipher import AES
import zlib
import struct


tag_id_to_string_map = {
    asn1.Numbers.Boolean: "BOOLEAN",
    asn1.Numbers.Integer: "INTEGER",
    asn1.Numbers.BitString: "BIT STRING",
    asn1.Numbers.OctetString: "OCTET STRING",
    asn1.Numbers.Null: "NULL",
    asn1.Numbers.ObjectIdentifier: "OBJECT",
    asn1.Numbers.PrintableString: "PRINTABLESTRING",
    asn1.Numbers.IA5String: "IA5STRING",
    asn1.Numbers.UTCTime: "UTCTIME",
    asn1.Numbers.Enumerated: "ENUMERATED",
    asn1.Numbers.Sequence: "SEQUENCE",
    asn1.Numbers.Set: "SET"
}

class_id_to_string_map = {
    asn1.Classes.Universal: "U",
    asn1.Classes.Application: "A",
    asn1.Classes.Context: "C",
    asn1.Classes.Private: "P"
}

object_id_to_string_map = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",

    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",

    "2.5.4.3": "commonName",
    "2.5.4.4": "surname",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.9": "streetAddress",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.4.12": "title",
    "2.5.4.13": "description",
    "2.5.4.42": "givenName",

    "1.2.840.113549.1.9.1": "emailAddress",

    "2.5.29.14": "X509v3 Subject Key Identifier",
    "2.5.29.15": "X509v3 Key Usage",
    "2.5.29.16": "X509v3 Private Key Usage Period",
    "2.5.29.17": "X509v3 Subject Alternative Name",
    "2.5.29.18": "X509v3 Issuer Alternative Name",
    "2.5.29.19": "X509v3 Basic Constraints",
    "2.5.29.30": "X509v3 Name Constraints",
    "2.5.29.31": "X509v3 CRL Distribution Points",
    "2.5.29.32": "X509v3 Certificate Policies Extension",
    "2.5.29.33": "X509v3 Policy Mappings",
    "2.5.29.35": "X509v3 Authority Key Identifier",
    "2.5.29.36": "X509v3 Policy Constraints",
    "2.5.29.37": "X509v3 Extended Key Usage"
}

def tag_id_to_string(identifier):
    """Return a string representation of a ASN.1 id."""
    if identifier in tag_id_to_string_map:
        return tag_id_to_string_map[identifier]
    return '{:#02x}'.format(identifier)

def class_id_to_string(identifier):
    """Return a string representation of an ASN.1 class."""
    if identifier in class_id_to_string_map:
        return class_id_to_string_map[identifier]
    raise ValueError('Illegal class: {:#02x}'.format(identifier))

def object_identifier_to_string(identifier):
    if identifier in object_id_to_string_map:
        return object_id_to_string_map[identifier]
    return identifier

def value_to_string(tag_number, value):
    if tag_number == asn1.Numbers.ObjectIdentifier:
        return object_identifier_to_string(value)
    elif isinstance(value, bytes):
        return value
        #return '0x' + str(binascii.hexlify(value).upper())
    elif isinstance(value, str):
        return value
    else:
        return repr(value)

QUAD = struct.Struct('>Q')

def aes_unwrap_key_and_iv(kek, wrapped):
    n = int(len(wrapped)/8 - 1)
    #NOTE: R[0] is never accessed, left in for consistency with RFC indices
    R = [None]+[wrapped[i*8:i*8+8] for i in range(1, n+1)]
    A = QUAD.unpack(wrapped[:8])[0]
    decrypt = AES.new(kek, AES.MODE_ECB).decrypt
    for j in range(5,-1,-1): #counting down
        for i in range(n, 0, -1): #(n, n-1, ..., 1)
            ciphertext = QUAD.pack(A^(n*j+i)) + R[i]
            B = decrypt(ciphertext)
            A = QUAD.unpack(B[:8])[0]
            R[i] = B[8:]
    return b"".join(R[1:]), A


def aes_unwrap_key(kek, wrapped, iv=0xa6a6a6a6a6a6a6a6):
    '''
    key wrapping as defined in RFC 3394
    http://www.ietf.org/rfc/rfc3394.txt
    '''
    key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    if key_iv != iv:
        raise ValueError("Integrity Check Failed: "+hex(key_iv)+" (expected "+hex(iv)+")")
    return key

dblob = None
wrapkey = None
nonce = None
encdata = None

def pretty_process_ref(input_stream, indent=0):
    """Pretty print ASN.1 data."""
    global dblob
    global wrapkey
    global nonce
    global encdata

    while not input_stream.eof():
        tag = input_stream.peek()
        if tag.typ == asn1.Types.Primitive:
            tag, value = input_stream.read()
            #output_stream.write(' ' * indent)
            if(tag_id_to_string(tag.nr) == "OCTET STRING"):
                string3 = value_to_string(tag.nr, value)
                if(len(string3) == 262 or  len(string3) == 178):
                    dblob = value_to_string(tag.nr, value)
                elif(len(string3) == 40):
                    wrapkey = value_to_string(tag.nr, value)
                elif(len(string3) == 12):
                    nonce = value_to_string(tag.nr, value)
                #else:
                    #output_encdata.write(value_to_string(tag.nr, value))
            if((tag.nr == 0) & (tag.typ == 0) & (tag.cls == 128)):
                encdata = value_to_string(tag.nr, value)
        elif tag.typ == asn1.Types.Constructed:
            input_stream.enter()
            pretty_process_ref(input_stream, indent + 2)
            input_stream.leave()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--sid", metavar="SID", dest="sid")
    parser.add_argument("--masterkey", required=True, metavar="DIRECTORY", dest="masterkeydir")
    parser.add_argument("--sysmasterkey", required=False, metavar="DIRECTORY", dest="sysmasterkeydir")
    parser.add_argument("--system", required=False, metavar="FILE", dest="sysfile")
    parser.add_argument("--security", required=False, metavar="FILE", dest="secfile")
    parser.add_argument("--password", required=False, metavar="PASSWORD", dest="password")
    parser.add_argument("--hash", required=False, metavar="PASSWORD", dest="hash")
    parser.add_argument("--outfile", required=False, metavar="FILE", dest="outfile")
    parser.add_argument("--base64file", required=False, metavar="FILE", dest="b64file")
    parser.add_argument("--syskey", required=False, metavar="PASSWORD", dest="syskey",
                        help="DPAPI_SYSTEM string. 01000000...")
    parser.add_argument("--pkey", required=False, help="Private domain KEY", dest="pkey")

    parser.add_argument("--debug", required=False, action="store_true", dest="debug")
    # help="lines with base64-encoded password blobs")

    options = parser.parse_args()

    if options.masterkeydir:
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
    sysdecr =0
    if options.sysmasterkeydir and options.sysfile and options.secfile:
        systemmkp = masterkey.MasterKeyPool()
        systemmkp.loadDirectory(options.sysmasterkeydir)
        reg = registry.Regedit()
        secrets = reg.get_lsa_secrets(options.secfile, options.sysfile)
        dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']
        systemmkp.addSystemCredential(dpapi_system)
        sysdecr = systemmkp.try_credential_hash(None, None)

    if options.pkey:
        decrn = mkp.try_domain(options.pkey)
        if decrn > 0:
            print("Decrypted: " + str(decrn))
            if options.debug:
                for mkl in mkp.keys.values():  # mkl - list with mk, mkbackup, mkdomain
                    for mk in mkl:
                        print(mk.guid)

    if options.password and options.sid:
        #print(mkp)
        decrn = mkp.try_credential(options.sid, options.password)
        print("Decrypted masterkeys: " + str(decrn))

    if options.hash and options.sid:
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
        options.hash = binascii.unhexlify(options.hash)
        decrn = mkp.try_credential_hash(options.sid, options.hash)
        print("Decrypted masterkeys: " + str(decrn))
        # print mkp

    if options.syskey:
        mkp.addSystemCredential(binascii.unhexlify(options.syskey))
        decrn = mkp.try_credential_hash(None, None)
        print("Decrypted masterkeys: " + str(decrn))

    if decrn == 0:
        print("No decrypted masterkeys ! ")
        print("Exiting..")
        exit()

    if options.b64file:
        input_file = open(options.b64file, 'rb')
        rawdata = input_file.readlines()

        rawdata = b''.join(rawdata)
        if (rawdata[3:6] == b"3-1") :
            input_data = base64.b64decode(rawdata[6:])
        else:
            input_data = base64.b64decode(rawdata)

        decoder = asn1.Decoder()
        decoder.start(input_data)
        pretty_process_ref(decoder)

        #to fix errror with newbytes in python2
        blob2 = binascii.unhexlify(binascii.hexlify(dblob))

        #probe = GenericDecryptor(blob2)
        dpapiprobe = probe.DPAPIProbe(dblob)
        if options.debug: print(dpapiprobe)
        if dpapiprobe.try_decrypt_with_password(options.password, mkp, options.sid,):
            if options.debug:   print("Decrypted Blob: %s" % binascii.hexlify(dpapiprobe.cleartext))
        else:
            print("DPAPI blob is not decrypted! Can't continue")
            exit(1)

        if options.debug: print("wrapkey: ", wrapkey)
        if options.debug: print("nonce: ", nonce)
        if options.debug: print("encdata: ", encdata)


        bigKEK = dpapiprobe.cleartext
        bigKEK = binascii.unhexlify(binascii.hexlify(bigKEK))
        bigwrapped = wrapkey
        bigkey = aes_unwrap_key(bigKEK, bigwrapped)
        bigiv = nonce
        try:
            bigcipher = AES.new(bigkey, AES.MODE_GCM, bigiv)
            bigplain = bigcipher.decrypt(encdata)
        except:
            print("AES is not decrypted! Can't continue")
            exit(1)

        if options.debug: print("Decrypted data in hex: %s " % binascii.hexlify(bigplain))

        try:
            bigdeflated = zlib.decompress(bigplain[4:])
        except:
            print("Error in deflating... Can't continue")
            exit(1)

        print("===========Decrypted OK !==========")

        if options.debug:   print("Deflated data: %s" % bigdeflated)

        if options.outfile:
            outfile = open(options.outfile, 'wb')
            outfile.write(bigdeflated)

        if len(bigdeflated)>0:
            startind = bigdeflated.find(b'0.A')
            endind = bigdeflated.find(b'\x00', startind)
            refresh_token = bigdeflated[startind:endind]
            print("Refresh token: %s" % refresh_token.decode())

        if len(bigdeflated) and sysdecr >0:
            startind = bigdeflated.find(b'AQAAAA')
            endind = bigdeflated.find(b'\x00',startind)
            sysblob = base64.b64decode(bigdeflated[startind:endind])[8:]
            dpapiblob = blob.DPAPIBlob(sysblob)
            mks = systemmkp.getMasterKeys(dpapiblob.mkguid.encode())
            for mk in mks:
                if mk.decrypted:
                    dpapiblob.decrypt(mk.get_key())
                    if dpapiblob.decrypted:
                        print(('-' * 79))
                        print('System key Blob Decrypted:')
                        print((dpapiblob.cleartext.hex()))

    exit()
