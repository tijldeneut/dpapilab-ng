#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2020, Photubias <tijl.deneut@howest.be>
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
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
""" Windows Crypto Keys offline and online decryptor (& PIN brute forcer).
    C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys
    ==> These contain ECS or RSA Public and Private keys
"""
## The default (9999) will perform a brute force of all 4 digit PIN combinations
iMaxPIN = 9999

import optparse, os, sys, time, hashlib, binascii
from pathlib import Path

try:
    from dpapick3 import blob, masterkey, registry
    from dpapick3.probes.certificate import PrivateKeyBlob, BcryptPrivateKeyBlob
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or len(args) != 1:
        sys.exit('You must provide crypto keys directory.')
    if not options.pinguid and (options.pin or options.pinbrute or options.pinexport):
        sys.exit('You must provide a pinGUID when trying to decrypt, brute force or export with PIN (run ngcparse.py first).')
    if options.pinguid and not (options.pin or options.pinbrute or options.pinexport):
        sys.exit('You must provide a PIN or enable the brute force / export hash option.')
    if options.masterkeydir and (not options.system or not options.security):
        sys.exit('You must provide system and security hives.')

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def parseTimestamp(bData):
    iTimestamp = int(reverseByte(bData).hex(), 16)
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(iTimestamp / 10000000 - 11644473600))

def parseFile(bData, boolVerbose = False):
    iType = int(reverseByte(bData[:4]).hex(), 16) ## followed by 4 bytes unknown
    iDescrLen = int(reverseByte(bData[8:12]).hex(), 16) ## followed by 2 bytes unknown
    iNumberOfFields = int(reverseByte(bData[14:16]).hex(), 16) ## followed by 2 bytes unknown
    sDescription = bData[44:44+iDescrLen].decode('UTF-16LE',errors='ignore')
    if boolVerbose: print('[+] File Descriptor : ' + sDescription)
    bRemainder = bData[44+iDescrLen:] ## Start of the data fields
    arrFieldData = []
    for i in range(0,iNumberOfFields):
        ## FieldLength is at bData 16 + 4 * i
        iFieldLen = int(reverseByte(bData[16+(4*i):16+(4*i)+4]).hex(), 16)
        bField = bRemainder[:iFieldLen]
        arrFieldData.append(bField)
        bRemainder = bRemainder[iFieldLen:]
    return (sDescription, arrFieldData)

def parsePrivateKeyProperties(hPKP, boolVerbose = False):
    def parseProperty(bProperty, boolVerbose = False):
        bStructLen = bProperty[:4]
        iType = int(reverseByte(bProperty[4:8]).hex(), 16)
        bUnk = bProperty[8:12]
        iNameLength = int(reverseByte(bProperty[12:16]).hex(), 16)
        iPropLength = int(reverseByte(bProperty[16:20]).hex(), 16)
        bName = bProperty[20:(20+iNameLength)]
        bProperty = bProperty[(20+iNameLength):(20+iNameLength+iPropLength)]
        if boolVerbose:
            print('Name  : ' + bName.decode('UTF-16LE',errors='ignore'))
            print('Value : ' + bProperty.hex())
        return {'Name':bName, 'Value':bProperty}
        
    bRest = bytes.fromhex(hPKP)
    arrProperties = []
    while not bRest == b'':
        iSize = int(reverseByte(bRest[:4]).hex(), 16)
        bProperty = bRest[:iSize]
        bRest = bRest[iSize:]
        arrProperties.append(parseProperty(bProperty))
    if boolVerbose:
        for prop in arrProperties:
            if prop['Name'].decode('UTF-16LE',errors='ignore') == 'NgcSoftwareKeyPbkdf2Salt':
                print('[+] Salt                 : ' + prop['Value'].hex())
            elif prop['Name'].decode('UTF-16LE',errors='ignore') == 'NgcSoftwareKeyPbkdf2Round':
                print('[+] Rounds               : 0x' + reverseByte(prop['Value']).hex() + ' (' + str(int(reverseByte(prop['Value']).hex(),16)) + ')' )
                
    return arrProperties

def parseField1(bData, boolVerbose = True):
    iSizeTotalHeader = int(reverseByte(bData[:4]).hex(), 16) ## then 8 bytes unk
    iSizeHeader1 = int(reverseByte(bData[12:16]).hex(), 16)
    iSizeHeader2 = int(reverseByte(bData[16:20]).hex(), 16)
    sHeader1 = bData[20:20+iSizeHeader1].decode('UTF-16LE',errors='ignore')
    sHeader2 = parseTimestamp(bData[20+iSizeHeader1:20+iSizeHeader1+iSizeHeader2])
    if boolVerbose:
        print('[+] ' + sHeader1 + '             : ' + sHeader2)
    bRemainder = bData[iSizeTotalHeader:] ## Next 4 bytes should be the size of this remainder
    if len(bRemainder) == 0:
        print('[-] Not able to pearse Field 1')
        return None
    iRemainderSize = int(reverseByte(bRemainder[:4]).hex(), 16)
    if not len(bRemainder) == iRemainderSize: 
        print('[-] Not able to pearse Field 1')
        return None
    iRemainderSize = int(reverseByte(bRemainder[16:20]).hex(), 16) ## not so important, should be remaining size
    bRemainder = bRemainder[20:]
    if not len(bRemainder) == iRemainderSize: 
        print('[-] Not able to pearse Data of Field 1')
        return None
    sKeyType = bRemainder[:4].decode(errors='ignore')
    iBitSize = int(reverseByte(bRemainder[4:8]).hex(), 16) ## then 4 bytes Unk
    iByteSize = int(reverseByte(bRemainder[12:16]).hex(), 16) ## then 11 bytes Unk
    bKey = bRemainder[27:27+iByteSize]
    if boolVerbose:
        print('[+] Key Type             : ' + sKeyType)
        #print('[+] Key Size: ' + str(iByteSize) + ' (' + str(iBitSize) + ')')  ## This is not correct in case of ECS keys
        print('[+] The Public Key (hex) : ' + bKey.hex())

def decryptWithPIN(mk, pkBlob, sSalt, iRounds, sPIN):
    sHexPIN = ''
    if not len(sPIN) == 64:
        sHexPIN = sPIN.encode().hex().upper().encode('UTF-16LE').hex() ## Windows HELLO PIN
    else:
        sHexPIN = sPIN.upper().encode('UTF-16LE').hex()
    bPIN = hashlib.pbkdf2_hmac('sha256', bytes.fromhex(sHexPIN), bytes.fromhex(sSalt), iRounds).hex().upper().encode('UTF-16LE')
    #print(hashlib.pbkdf2_hmac('sha256', bytes.fromhex(sHexPIN), bytes.fromhex(sSalt), iRounds).hex())
    ## Current bPIN is what is fed into "ncrypt.dll", together with the input from the NGC protector
    #print(bPIN.hex())
    bPIN = hashlib.sha512(bPIN).digest()
    pkBlob.decrypt(mk.get_key(), entropy = b'xT5rZW5qVVbrvpuA\x00', smartCardSecret = bPIN)
    return pkBlob

def exportHASH(mk, pkBlob, sSalt, iRounds, sPINGUID):
    ## HASH FORMAT: $WINHELLO$*SHA512*rounds*salt*sign*masterkey*hmac*verify*entropy
    ### Sources and thanks: https://hashcat.net/forum/thread-10461.html
    bEntropy = b'xT5rZW5qVVbrvpuA\x00'
    sHash = f'$WINHELLO$*{pkBlob.hashAlgo.name.upper()}*{iRounds}*{sSalt}*{pkBlob.sign.hex()}*{mk.get_key().hex()}*{pkBlob.hmac.hex()}*{pkBlob.blob.hex()}*{bEntropy.hex()}'
    sFilename = '{}.hc28100'.format(sPINGUID.replace('{','').replace('}',''))
    open(sFilename,'a').write(sHash+'\n')
    print(f'\n[!] Exported PIN hash to file: {sFilename}')
    return

def brutePIN(mk, pkBlob, sSalt, iRounds):
    for i in range(0, iMaxPIN): ## Default 9999
        PIN = f"{i:04d}"  ## Watch out, when Max PIN is e.g. 99999, it will start from 0000 to 99999
        if int(PIN)%1000 == 0: print('[!] Trying PINs ' + PIN + ' - ' + str(1000+int(PIN)))
        pkResult = decryptWithPIN(mk, pkBlob, sSalt, iRounds, PIN)
        if pkResult.decrypted:
            print('[+] Found PIN : ' + PIN)
            return (pkResult, PIN)
    return (pkBlob, '')


def savePEM(private_key_hex: str, pem_path: str, pemname: str):
    try:
        rsa_private_key = PrivateKeyBlob.RSAKey(binascii.a2b_hex(private_key_hex))
    except:
        print("[-] Error parsing private key as Full RSA Key")
        print("[*] Trying parsing private key as Bcrypt RSA Key...")
        try:
            rsa_private_key = BcryptPrivateKeyBlob.RSAKey(binascii.a2b_hex(private_key_hex))
        except:
            print("[-] Error parsing private key as Bcrypt RSA Key")
            return
    pem_path = str(Path(pem_path).absolute())+"/"+pemname+".pem"
    Path(pem_path).write_bytes(rsa_private_key.export_pkcs12())
    print("[+] PEM saved in {}".format(pem_path))


def main(sCryptoFolder, sMasterkey, sSystem, sSecurity, sPIN, sPINGUID, boolOutput = True, pemexport="", sid=None, password=None):
    ## if sPIN == '', do brute force
    if sSystem:
        reg = registry.Regedit()
        secrets = reg.get_lsa_secrets(sSecurity, sSystem)
        dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']
        
    mkp = masterkey.MasterKeyPool()
    if sMasterkey:
        mkp.loadDirectory(sMasterkey)
        mkp.addSystemCredential(dpapi_system)
        decrn=mkp.try_credential_hash(None, None)
        #print("Decrypted keys %d" % decrn)

    if sid and password:
            mkp.try_credential(options.sid, options.password)

    for root, _, files in os.walk(sCryptoFolder):
        for sFile in files:
            filepath = os.path.join(root, sFile)
            with open(filepath, 'rb') as f:
                file_data = f.read()
                sInfo, arrFieldData = parseFile(file_data)
                if boolOutput:
                    print('-' * 10 + ' ' + sFile + ' ' + '-' * 10)
                    print('[+] KEY GUID             : ' + sInfo)
                ### Field 2 and 3 are DPAPI Blob
                parseField1(arrFieldData[0], boolOutput)
                ## Private Key Properties should work with static Entropy '6jnkd5J3ZdQDtrsu'
                blobPrivateKeyProperties = arrFieldData[1]
                pkpBlob = blob.DPAPIBlob(blobPrivateKeyProperties)
                mks = mkp.getMasterKeys(pkpBlob.mkguid.encode())
                for mk in mks:
                    if mk.decrypted:
                        pkpBlob.decrypt(mk.get_key(), entropy = b'6jnkd5J3ZdQDtrsu\x00')
                        if pkpBlob.decrypted:
                            if boolOutput: print('[+] Private Key Properties decrypted!')
                            arrPrivateKeyProperties = parsePrivateKeyProperties(pkpBlob.cleartext.hex(), boolOutput)
                
                ## Private Key, we can try, but the entropy is either unknown static or variable (some are 'xT5rZW5qVVbrvpuA')
                blobPrivateKey = arrFieldData[2]
                pkBlob = blob.DPAPIBlob(blobPrivateKey)
                mks = mkp.getMasterKeys(pkBlob.mkguid.encode())
                for mk in mks:
                    if mk.decrypted:
                        pkBlob.decrypt(mk.get_key(), entropy = b'xT5rZW5qVVbrvpuA\x00', strongPassword=None)
                        if pkBlob.decrypted and boolOutput:
                            print('[+] Private Key decrypted : ')
                            print('    ' + pkBlob.cleartext.hex())
                            if pemexport:
                                savePEM(pkBlob.cleartext.hex(), pem_path=pemexport, pemname=sInfo)
                        else:
                            if sPINGUID and sPINGUID in sInfo and arrPrivateKeyProperties:
                                for sProperty in arrPrivateKeyProperties:
                                    if sProperty['Name'].decode('UTF-16LE',errors='ignore') == 'NgcSoftwareKeyPbkdf2Salt': sSalt = sProperty['Value'].hex()
                                    elif sProperty['Name'].decode('UTF-16LE',errors='ignore') == 'NgcSoftwareKeyPbkdf2Round': iRounds = int(reverseByte(sProperty['Value']).hex(),16)
                                if sPIN and not sPIN == '':
                                    pkResult = decryptWithPIN(mk, pkBlob, sSalt, iRounds, sPIN)
                                elif options.pinbrute:
                                    if boolOutput: print('[!] Trying PIN brute force 0000 through {}, this will take some time '.format(iMaxPIN))
                                    (pkResult, sPIN) = brutePIN(mk, pkBlob, sSalt, iRounds)
                                elif options.pinexport:
                                    exportHASH(mk, pkBlob, sSalt, iRounds, sPINGUID)
                                    pkResult = None
                                if pkResult and pkResult.decrypted:
                                    if boolOutput:
                                        print('[+] Private Key decrypted with PIN (' + sPIN + ') :')
                                        print('    ' + pkBlob.cleartext.hex())
                                    else: ## no bool output means: called by other script that is only interested in this cleartext data
                                        return pkBlob.cleartext
                                else:
                                    if sPIN and boolOutput: print('[-] Decryption with PIN tried but failed')
                            else:
                                if boolOutput: print('[-] Entropy unknown for ' + pkBlob.description.decode())
                            
            if boolOutput: print('')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] CryptoKeys Directory\n\n'
        'It decrypts Crypto Key blobs stored in\n'
        '\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\Keys\n'
        'You must provide such directory, SYSTEM and SECURITY hives and,\n'
        'finally, the system DPAPI MasterKeys, stored in\n'
        '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\n'
        'Optionally enter a Windows Hello GUID and (PIN or pinbrute) to decrypt certain fields')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='FOLDER',default=os.path.join('Windows','System32','Microsoft','Protect','S-1-5-18','User') , dest='masterkeydir', help=r'System Masterkey folder; default: Windows\System32\Microsoft\Protect\S-1-5-18\User')
    parser.add_option('--system', metavar='HIVE', default=os.path.join('Windows','System32','config','SYSTEM'), help=r'SYSTEM file; default: Windows\System32\config\SYSTEM')
    parser.add_option('--security', metavar='HIVE', default=os.path.join('Windows','System32','config','SECURITY'), help=r'SECURITY file; default: Windows\System32\config\SECURITY')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pinguid', metavar='STRING', dest='pinguid', help='Specify the GUID to try PIN on')
    parser.add_option('--pin', metavar='STRING', dest='pin', help='Try decryption with PIN')
    parser.add_option('--pinexport', metavar='BOOL', dest='pinexport', action="store_true", help='When simple brute force fails, export PIN as Hashcat hash to a file hc28100')
    parser.add_option('--pinbrute', metavar='BOOL', dest='pinbrute', action="store_true", help='Brute force PIN 0000 to 9999')
    parser.add_option('--pemexport', metavar='FOLDER', dest='pemexport', help='Folder to export private RSA keys as PEM files')

    (options, args) = parser.parse_args()

    check_parameters(options, args)
    
    if options.pinbrute: sPIN = ''
    else: sPIN = options.pin
    main(args[0], options.masterkeydir, options.system, options.security, sPIN, options.pinguid, True, options.pemexport, options.sid, options.password)
