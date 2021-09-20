#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r'''
Copyright 2021, Tijl "Photubias" Deneut <tijl.deneut@howest.be>
Source and credits: https://github.com/mis-team/dpapick/blob/master/examples/efs.py

This script converts RSA certs from
%APPDATA%/Microsoft/SystemCertificates/My/Certificates
and (DPAPI encrypted) RSA private keys from
%APPDATA%/Microsoft/Crypto/RSA/<SID>
and turn them into unprotected PFX file(s)

DPAPI decryption needs either:
User MasterKey + User SID + User password or hash
User MasterKey + Domain PVK
Decrypted Masterkey (64bytes, 128 HEX characters)

Prerequirement: DPAPick3

The resulting PFX files can be imported into any Windows machine to read EFS folders, or using Linux:
ntfsdecrypt -k <name.pfx> /dev/sda Users\User\Desktop\Encrypted_Folder\hiddenfile.txt
'''

import argparse, os, base64, warnings, re, OpenSSL
warnings.filterwarnings("ignore")
try:
    from dpapick3 import blob, masterkey
    from dpapick3.probes import certificate
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3')

def parseArgs():
    print('[!] Welcome. To decrypt, one of three combo\'s is required: \n'
          'Decrypted Masterkey / MK file, SID and User Pwd or Hash / MK file and Domain PVK\n'
          'RSA public cert path:\n'
          '%APPDATA%\\Microsoft\\SystemCertificates\\My\\Certificates\n'
          'RSA private key path:\n'
          '%APPDATA%\\Microsoft\\Crypto\\RSA\\<SID>')
    oParser = argparse.ArgumentParser()
    oParser.add_argument('--rsapub', '-r', metavar='FOLDER', help='Folder containing RSA public certs', required=True)
    oParser.add_argument('--rsapriv', '-c', metavar='FOLDER', help='Folder containing RSA private keys', required=True)
    oParser.add_argument('--outfolder', '-o', metavar='FOLDER', help='Folder to export PFX (optional)')
    oParser.add_argument('--mkfile', '-m', metavar='FILE', help='GUID file or folder to get Masterkey(s) from (optional)')
    oParser.add_argument('--sid', '-s', metavar='SID', help='User SID (optional)')
    oParser.add_argument('--pwdhash', '-a', metavar='HASH', help='User password SHA1 hash (optional)')
    oParser.add_argument('--password', '-p', metavar='PASS', help='User password (optional)')
    oParser.add_argument('--pvk', '-d', metavar='FILE', help='AD cert in PVK format (optional)')
    oParser.add_argument('--verbose', '-v', action = 'store_true', default = False, help='Print decrypted creds/cookies to console (optional)')
    oArgs = oParser.parse_args()

    if not os.path.isdir(oArgs.rsapub): exit('[-] Error: Please provide RSA public cert folder')
    if not os.path.isdir(oArgs.rsapriv): exit('[-] Error: Please provide RSA private key folder (crypto folder)')
    if oArgs.pvk and not os.path.isfile(oArgs.pvk): exit('[-] Error: File not found: ' + oArgs.pvk)
    if oArgs.mkfile: oArgs.mkfile = oArgs.mkfile.replace('*','')
    if oArgs.mkfile and not os.path.isfile(oArgs.mkfile) and not os.path.isdir(oArgs.mkfile): exit('[-] Error: File/folder not found: ' + oArgs.mkfile)
    if oArgs.mkfile and not oArgs.sid: 
        try:
            oArgs.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", oArgs.mkfile)[0]
            print('[+] Detected SID: ' + oArgs.sid)
        except: pass
    if oArgs.mkfile and oArgs.sid and not oArgs.password and not oArgs.pwdhash: 
        oArgs.pwdhash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        # On older systems: oArgs.pwdhash = '31d6cfe0d16ae931b73c59d7e0c089c0'
        print('[+] No password data provided, using empty hash')
    if oArgs.pwdhash: oArgs.pwdhash = bytes.fromhex(oArgs.pwdhash)
    return oArgs

if __name__ == '__main__':
    oArgs = parseArgs()
    lstKeys, lstCerts, lstMasterkeys = [], [], []
    bMasterkey = oMKP = None

    ##  All other options require one or more MK files, using MK Pool
    if oArgs.mkfile:
        oMKP = masterkey.MasterKeyPool()
        if os.path.isfile(oArgs.mkfile): 
            oMKP.addMasterKey(open(oArgs.mkfile,'rb').read())
        else: 
            oMKP.loadDirectory(oArgs.mkfile)
            if oArgs.verbose: print('[!] Imported {} DPAPI master keys'.format(str(len(list(oMKP.keys)))))
    
    ## Option 1: the PVK domain key to decrypt the MK key
    if oMKP and oArgs.pvk:
        print('[!] Try MK decryption with the PVK domain key')
        if oMKP.try_domain(oArgs.pvk) > 0:
            for bMKGUID in list(oMKP.keys):
                oMK = oMKP.getMasterKeys(bMKGUID)[0]
                if oMK.decrypted: 
                    bMasterkey = oMK.get_key()
                    print('[+] Success, user masterkey decrypted: ' + bMasterkey.hex())
    
    ## Option 2: User SID + password (hash)
    if oArgs.mkfile and oArgs.sid and (oArgs.password or oArgs.pwdhash): 
        print('[!] Try MK decryption with user details, might take some time')
        if oArgs.password: oMKP.try_credential(oArgs.sid, oArgs.password)
        else: oMKP.try_credential_hash(oArgs.sid, oArgs.pwdhash)
        for bMKGUID in list(oMKP.keys):
            oMK = oMKP.getMasterKeys(bMKGUID)[0]
            if oMK.decrypted: 
                if not oMK.get_key() in lstMasterkeys: lstMasterkeys.append(oMK.get_key())
                if oArgs.verbose: print('[+] DPAPI MK decrypted: ' + oMK.get_key().hex())

    if not bMasterkey and not oMKP: exit('[-] Error: no masterkeys provided')

    ## Parse and DPAPI decrypt RSA Private keys
    for sFilename in os.listdir(oArgs.rsapriv):
        with open(os.path.join(oArgs.rsapriv, sFilename), 'rb') as oFile:
            oBlob = certificate.PrivateKeyBlob(oFile.read())
            if oBlob.try_decrypt_with_hash(oArgs.pwdhash, oMKP, oArgs.sid):
                print('[+] Decrypted private key %s from %s' % (oBlob.description.decode(), os.path.join(oArgs.rsapriv, sFilename)))
                #with open('%s.rsa' % str(oBlob.description).rstrip(b'\x00'), 'wb') as rsa_out:  rsa_out.write(oBlob.export()); rsa_out.close()
                oBlob.description = oBlob.description.rstrip(b'\x00')
                lstKeys.append(oBlob)
    
    ## Parse RSA Public keys
    for sFilename in os.listdir(oArgs.rsapub):
        with open(os.path.join(oArgs.rsapub, sFilename), 'rb') as oFile:
            oCert = certificate.Cert(oFile.read())
            if hasattr(oCert, 'name') and hasattr(oCert, 'certificate'):
                lstCerts.append(oCert)
                print('[+] Found certificate associated with key %s: %s' % (oCert.name, os.path.join(oArgs.rsapub, sFilename)))

    ## Create PFX and save as necessary
    for oKey in lstKeys:
        for oCert in lstCerts:
            if oKey.description.decode() == oCert.name:
                oP12 = OpenSSL.crypto.PKCS12()
                oP12.set_privatekey(OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, oKey.export()))
                oP12.set_certificate(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, oCert.certificate))
                if oArgs.outfolder and os.path.isdir(oArgs.outfolder):
                    print('[+] Writing to ' + os.path.join(oArgs.outfolder, oCert.name+'.pfx'))
                    with open(os.path.join(oArgs.outfolder, oCert.name+'.pfx'), 'wb') as oPFXFile: 
                        oPFXFile.write(oP12.export())
                        oPFXFile.close()
                print('[+] Successfully reassembled private key and certificate: %s.pfx' % (oCert.name))