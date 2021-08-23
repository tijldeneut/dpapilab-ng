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
"""DECRYPTING NGC SYSTEM VAULT FILES (VCRD) """
r"""  
Example command for live decryption:
Run as Admin
> reg save hklm\system system && reg save hklm\security security
> ngcvaultdec.py \Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28 --system=system --security=security --masterkey=\Windows\System32\Microsoft\Protect\S-1-5-18\User

Credential Providers in the Registry: SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers (with {D6886603-9D2F-4EB2-B667-1971041FA96B} having GUIDs)

--> The SCHEMA GUID determines the kind of VAULT credential:
VCSH FILE NAME == SCHEMA GUID == static for the type of Credential:
3e0e35be-1b77-43e7-b873-aed901b6275b == Domain Password
e69d7838-91b5-4fc9-89d5-230d4d4cc2bc == Domain Certificate
3c886ff3-2669-4aa2-a8fb-3f6759a77548 == Domain Extended
b2e033f5-5fde-450d-a1bd-3791f465720c == Pin Logon
b4b8a12b-183d-4908-9559-bd8bce72b58a == Picture Password
fec87291-14f6-40b6-bd98-7ff245986b26 == Biometric
1d4350a3-330d-4af9-b3ff-a927a45998ac == Next Generation Credential
"""

import optparse, os, sys, time
from Crypto.Cipher import AES

try:
    import dpapick3.blob as blob
    import dpapick3.masterkey as masterkey
    import dpapick3.registry as registry
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or len(args) != 1:
        sys.exit('You must provide a system vaults directory.')
    elif not os.path.isdir(args[0]):
        sys.exit('You must provide a system vaults directory.')
    if not options.masterkeydir:
        sys.exit('Cannot decrypt anything without master keys.')
    if not options.system or not options.security:
        sys.exit('You must provide SYSTEM and SECURITY hives.')

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def parseGUID(bData):
    return reverseByte(bData[:4]).hex() + '-' + reverseByte(bData[4:6]).hex() + '-' + reverseByte(bData[6:8]).hex() + '-' + bData[8:10].hex() + '-' + bData[10:].hex()

def parseTimestamp(bData):
    iTimestamp = int(reverseByte(bData).hex(), 16)
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(iTimestamp / 10000000 - 11644473600))

def getSchemaType(sGUID):
    if sGUID.lower() == '3e0e35be-1b77-43e7-b873-aed901b6275b': return 'Domain Password'
    elif sGUID.lower() == 'e69d7838-91b5-4fc9-89d5-230d4d4cc2bc': return 'Domain Certificate'
    elif sGUID.lower() == '3c886ff3-2669-4aa2-a8fb-3f6759a77548': return 'Domain Extended'
    elif sGUID.lower() == 'b2e033f5-5fde-450d-a1bd-3791f465720c': return 'Pin Logon'
    elif sGUID.lower() == 'b4b8a12b-183d-4908-9559-bd8bce72b58a': return 'Picture Password'
    elif sGUID.lower() == 'fec87291-14f6-40b6-bd98-7ff245986b26': return 'Biometric'
    elif sGUID.lower() == '1d4350a3-330d-4af9-b3ff-a927a45998ac': return 'Next Generation Credential'
    return 'Unknown'

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
        print('[-] MasterKey not found for blob.', file=sys.stderr)

    if blob.decrypted: return blob.cleartext
    else: return None

def parsePolicy(bData, boolVerbose = False):
    bVersion = reverseByte(bData[:4])
    sPolGuid = parseGUID(bData[4:20])
    iPolDescrLen = int(reverseByte(bData[20:24]).hex(), 16)
    sPolDescr = bData[24:24+iPolDescrLen].decode('utf-16le').strip('\x00')
    iOffset = 24 + iPolDescrLen + 4 + 4 + 4 ## Unk1, Unk2 & Unk3 contain Unknown bytes, usually 0x0 or 0x1
    bRemainder = bData[iOffset:] ## start of vpol_store(s)
    if boolVerbose:
        print('--- Policy MetaData ---')
        print('[+] GUID        : ' + sPolGuid)
        print('[+] Description : ' + sPolDescr)
    i = 0
    while len(bRemainder) >= 4:
        i += 1
        iStoreLen = int(reverseByte(bRemainder[:4]).hex(), 16)
        bRemainder = bRemainder[4:]
        if iStoreLen == 0: 
            bRemainder = ''
            continue
        else:
            sStoreGuid = parseGUID(bRemainder[:16])
            sStoreGuid2 = parseGUID(bRemainder[16:32])
            iBlobLen = int(reverseByte(bRemainder[32:36]).hex(), 16)
            bStoreBlob = blob.DPAPIBlob(bRemainder[36:36+iBlobLen])
            bRemainder = bRemainder[36+iStoreLen:]
        if boolVerbose: 
            if boolVerbose: print('-- Policy Store ' + str(i) + ' --')
            print('[+] GUID   : ' + sStoreGuid)
            print(bStoreBlob)
    return bStoreBlob

def parsePolicyEntries(bData, boolVerbose = False):
    bRemainder = bData
    arrKeys = []
    i = 0
    while len(bRemainder) >= 4:
        i += 1
        iEntryLen = int(reverseByte(bRemainder[:4]).hex(), 16)
        sType = bRemainder[12:16].decode(errors='ignore') ## KDBM == Kerberos Data Base Manager
        iDataLen = int(reverseByte(bRemainder[20:24]).hex(), 16)
        bEntry = bRemainder[24:24+iDataLen]
        bRemainder = bRemainder[4+iEntryLen:]
        arrKeys.append(bEntry)
        if boolVerbose:
            print('-- Policy Entry ' + str(i) + ' --')
            print('[+] Description : ' + sType)
            print('[+] Actual Key  : ' + bEntry.hex())
    return arrKeys[0], arrKeys[1]

def parseVCRD(bData, boolVerbose = False):
    ## VCRD == Meta Data + Array of Attribute Headers + Attributes themselves
    ## 1: Parse Meta Data
    sSchemaGUID = parseGUID(bData[0:16]) ## Then 4 bytes unk (0x3)
    sSchemaType = getSchemaType(sSchemaGUID)
    sLastUpdate = parseTimestamp(bData[20:28]) ## Then 8 bytes unk
    iDescrLen = int(reverseByte(bData[36:40]).hex(), 16)
    sDescription = bData[40:40+iDescrLen].decode('utf-16le').strip('\x00')
    bRemainder = bData[40+iDescrLen:]
    if boolVerbose:
        print('--- Vault MetaData ---')
        print('[+] Schema GUID  : ' + sSchemaGUID)
        print('[+] Last Updated : ' + sLastUpdate)
        print('[+] Description  : ' + sDescription)
    ## 2: Parse AttributeHeaders
    iAttrHeaderLen = int(reverseByte(bRemainder[:4]).hex(), 16)
    bHeaders = bRemainder[4:4+iAttrHeaderLen]
    arrAttrHeaders = []
    while len(bHeaders) > 0:
        iAttrID = int(reverseByte(bHeaders[:4]).hex(), 16)
        iAttrOffset = int(reverseByte(bHeaders[4:8]).hex(), 16)
        arrAttrHeaders.append((iAttrID, iAttrOffset))
        bHeaders = bHeaders[12:]
    if boolVerbose:
        for x in arrAttrHeaders: print('[+] Attribute ' + str(x[0]) + ' has VCRD offset ' + str(x[1]))
    ## 3: Parse Attributes
    bRemainder = bRemainder[4+iAttrHeaderLen:] ## we should now be in bData[arrAttrHeaders[0][1]:] (offset from the first attribute)
    bData = bIV = b''
    for x in range(0,len(arrAttrHeaders)):
        iAttrID = int(reverseByte(bRemainder[:4]).hex(), 16) ## Followed by 12 bytes of unk1, unk2 and unk3
        bRemainder = bRemainder[4+4+4+4:]
        ## Dirty: if 5th byte is '00', then byte 7 == dataLength. If not, then that is ID of the next attribute (and there is no data)
        if bRemainder[4] == 0:
            bRemainder = bRemainder[6:]
            iDataLen = int(reverseByte(bRemainder[:4]).hex(), 16)
            bRemainder = bRemainder[4:] ## this is now hasIV+(IVSize+IV)+DATA
            bHasIV = int(bRemainder[:1].hex(), 16) # 1 == IV, 0 == no IV and no 4 bytes
            if bHasIV == 1: 
                iIVLen = int(reverseByte(bRemainder[1:5]).hex(), 16)
                bIV = bRemainder[5:5+iIVLen]
                bData = bRemainder[5+iIVLen:iDataLen]
            else: 
                iIVLen = 0
                bIV = b''
                bRemainder = bRemainder[1:iDataLen]
        else:
            iSize = int(reverseByte(bRemainder[:4]).hex(), 16) ## should be zero
            bRemainder = bRemainder[4:]
    if boolVerbose:
        print('[+] IV   : ' + bIV.hex())
        print('[+] Data : ' + bData.hex())
    return (bIV, bData, sSchemaType)

def parseDecryptedAttribute(bData, boolVerbose = False):
    iVersion = int(reverseByte(bData[:4]).hex(), 16)
    iNumberOfContainers = int(reverseByte(bData[4:8]).hex(), 16) ## Then 4 bytes unk (0x1)
    bRemainder = bData[12:]
    dicContainers = {}
    for x in range(0,iNumberOfContainers):
        iID = int(reverseByte(bRemainder[:4]).hex(), 16)
        iSize = int(reverseByte(bRemainder[4:8]).hex(), 16)
        bData = bRemainder[8:8+iSize]
        dicContainers[iID] = bData
        bRemainder = bRemainder[8+iSize:]
        if boolVerbose:
            print('[+] Container ID   : ' + str(iID))
            print('[+] Container Data : ' + bData.hex())
    return dicContainers

def parseSID(bData):
    sResult = 'S-'
    sResult += str(bData[0]) + '-'
    sResult += str(bData[1]) + '-'
    sResult += str(bData[8]) + '-'
    sResult += str(int(reverseByte(bData[12:16]).hex(), 16)) + '-'
    sResult += str(int(reverseByte(bData[16:20]).hex(), 16)) + '-'
    sResult += str(int(reverseByte(bData[20:24]).hex(), 16)) + '-'
    sResult += str(int(reverseByte(bData[24:28]).hex(), 16))
    return sResult

def getUsername(sSOFTWARE, sSID):
    reg = registry.Regedit()
    return reg.getUsername(sSOFTWARE, sSID)

def parseFinalData(bData, boolVerbose = False):
    sType = reverseByte(bData[:4])
    iEncDataLen = int(reverseByte(bData[4:8]).hex(),16)
    iIVLen = int(reverseByte(bData[8:12]).hex(), 16)
    iEncPwdLen = int(reverseByte(bData[12:16]).hex(), 16)
    iLastLen = int(reverseByte(bData[16:20]).hex(), 16)
    iOffset = 20
    sEncData = bData[iOffset:iOffset + iEncDataLen].hex()
    iOffset += iEncDataLen
    sIV = bData[iOffset:iOffset + iIVLen].hex()
    iOffset += iIVLen
    sEncPwd = bData[iOffset:iOffset + iEncPwdLen].hex()
    iOffset += iEncPwdLen
    sLast = bData[iOffset:iOffset + iLastLen].hex()
    if boolVerbose:
        print('[+] EncData     : ' + sEncData)
        print('[+] IV          : ' + sIV)
        print('[+] EncPassword : ' + sEncPwd)
    return (sEncData, sIV, sEncPwd)

def main(sVaultFolder, sMasterkey, sSystem, sSecurity, sSoftware = None, boolOutput = True):
    ## Step 1: prepare DPAPI data (System MK pool)
    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(sMasterkey)
    
    reg = registry.Regedit()
    secrets = reg.get_lsa_secrets(sSecurity, sSystem)
    dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']
    mkp.addSystemCredential(dpapi_system)
    mkp.try_credential_hash(None, None)
    
    ## Step 2: Parse and DPAPI decrypt Policy.vpol
    vpol_filename = os.path.join(sVaultFolder, 'Policy.vpol')
    with open(vpol_filename, 'rb') as f: vpol_blob = parsePolicy(f.read())
    vpol_cleartext = decrypt_blob(mkp, vpol_blob)
    if not vpol_cleartext:
        exit('[-] Unable to decrypt Policy.vpol')
    bKeyAES128, bKeyAES256 = parsePolicyEntries(vpol_cleartext)
    
    ## Step 3: Parse and AES decrypt VCRD
    sUsername = ''
    arrResult = []
    for xfile in os.listdir(sVaultFolder):
        if xfile.lower().endswith('.vcrd'):
            filepath = os.path.join(sVaultFolder, xfile)
            if boolOutput: print('---- Working on ' + xfile + ' ----')
            with open(filepath, 'rb') as vcrdfile:
                bIV, bData, sSchemaType = parseVCRD(vcrdfile.read()) ## parseVCRD verifies the vault type (GUIDs at the top of this file)
                if bKeyAES256 and bData:
                    cipher = AES.new(bKeyAES256, AES.MODE_CBC, iv = bIV)
                    bDecrypted = cipher.decrypt(bData)
                    dicContainers = parseDecryptedAttribute(bDecrypted) ## dicContainers[ContainerID] = bData
                    if dicContainers[1].decode(errors='ignore').startswith('N\x00G\x00C\x00'): ## Should be "NGC Local Accoount Logon Vault Resource" in utf-16le
                        if boolOutput:
                            print('[+] Schema Type : ' + sSchemaType)
                            print('[+] User SID    : ' + parseSID(dicContainers[2]))
                        if sSoftware: 
                            sUsername = getUsername(sSoftware, parseSID(dicContainers[2]))
                            if boolOutput: print('[+] Username    : ' + sUsername)
                        arrResult = parseFinalData(dicContainers[3], boolOutput) ## Also found in the registry with reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\NgcPin\Credentials\S-1-5-21-1493826120-1374394018-1204472284-1001 /v EncryptedPassword
                    else:
                        if boolOutput:
                            print('[+] Schema Type        : ' + sSchemaType)
                            print('[+] HEX decrypted data : ' + dicContainers[3].hex())
                            try: print('[+] Decoded value      : ' + dicContainers[3].decode('utf-16le',errors='ignore'))
                            except: pass
            if boolOutput: print('#'*50)
    if arrResult == []: print('[-] No vaults found')
    return (sUsername, arrResult)

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] System_Vault_Directory\n\n'
        'It tries to decrypt System Vault VCRD files.\n'
        '\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault\\<GUID>\n'
        'Needs system MKs: \n'
        '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\n'
        'When SOFTWARE is provided, the username is parsed too')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--system', metavar='HIVE', dest='system')
    parser.add_option('--security', metavar='HIVE', dest='security')
    parser.add_option('--software', metavar='HIVE', dest='software', help='Optional, for username retrieval')

    (options, args) = parser.parse_args()

    check_parameters(options, args)
    
    ##main(sVaultFolder, sMasterkey, sSystem, sSecurity, boolOutput = True):
    sSoftware = None
    if options.software: sSoftware = options.software
    main(args[0], options.masterkeydir, options.system, options.security, sSoftware)
    
