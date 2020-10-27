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
""" Windows system WiFi password offline and online decryptor.
    C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys
"""

import optparse, os, re, sys, time

try:
    import dpapick_py3.blob as blob
    import dpapick_py3.masterkey as masterkey
    import dpapick_py3.registry as registry
except ImportError:
    raise ImportError('Missing dpapick_py3 folder, get it or set PYTHONPATH.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or len(args) != 1:
        sys.exit('You must provide crypto keys directory.')
    if not options.security or not options.system:
        sys.exit('You must provide SYSTEM and SECURITY hives.')
    if not options.masterkeydir:
        sys.exit('You must provide the system DPAPI folder, see <usage>.')

def reverseByte(sByteInput):
    sReversed = ''
    sHexInput = sByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def parseTimestamp(bData):
    iTimestamp = int(reverseByte(bData).hex(), 16)
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(iTimestamp / 10000000 - 11644473600))

def parseFile(bData, boolVerbose = False):
    iType = int(reverseByte(bData[:4]).hex(), 16) ## followed by 4 bytes unknown
    iDescrLen = int(reverseByte(bData[8:12]).hex(), 16) ## followed by 2 bytes unknown
    iNumberOfFields = int(reverseByte(bData[14:16]).hex(), 16) ## followed by 2 bytes unknown
    sDescription = bData[44:44+iDescrLen].decode('utf-16le',errors='ignore')
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
            print('Name  : ' + bName.decode('utf-16le',errors='ignore'))
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
            if prop['Name'].decode('utf-16le',errors='ignore') == 'NgcSoftwareKeyPbkdf2Salt':
                print('[+] Salt   : ' + prop['Value'].hex())
            elif prop['Name'].decode('utf-16le',errors='ignore') == 'NgcSoftwareKeyPbkdf2Round':
                print('[+] Rounds : 0x' + reverseByte(prop['Value']).hex() + ' (' + str(int(reverseByte(prop['Value']).hex(),16)) + ')' )
                
    return arrProperties

def parseField1(bData, boolVerbose = True):
    iSizeTotalHeader = int(reverseByte(bData[:4]).hex(), 16) ## then 8 bytes unk
    iSizeHeader1 = int(reverseByte(bData[12:16]).hex(), 16)
    iSizeHeader2 = int(reverseByte(bData[16:20]).hex(), 16)
    sHeader1 = bData[20:20+iSizeHeader1].decode('utf-16le',errors='ignore')
    sHeader2 = parseTimestamp(bData[20+iSizeHeader1:20+iSizeHeader1+iSizeHeader2])
    if boolVerbose:
        print('[+] ' + sHeader1 + ' : ' + sHeader2)
    bRemainder = bData[iSizeTotalHeader:] ## Next 4 bytes should be the size of this remainder
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
        print('[+] Key Type in Field1 : ' + sKeyType)
        #print('[+] Key Size in Field1 : ' + str(iByteSize) + ' (' + str(iBitSize) + ')')  ## This is not correct in case of ECS keys
        print('[+] The Key in Hex     : ' + bKey.hex())
    

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] CryptoKeys Directory\n\n'
        'It decrypts Crypto Key blobs stored in\n'
        '\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\Keys\n'
        'You must provide such directory, SYSTEM and SECURITY hives and,\n'
        'finally, the system DPAPI MasterKeys, stored in\n'
        '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User.')
    import hashlib
    parser = optparse.OptionParser(usage=usage)
    sBlob = '01000000D08C9DDF0115D1118C7A00C04FC297EB010000008E632C8B2907D8409DD6529E9C32FB9F0000000018000000500072006900760061007400650020004B0065007900000010660000000100002000000099747613F773C0B3139DA42735919717812DA306B0661624A5CB5EACA10932B3000000000E8000000002000020000000F81755F8C21934A9A09CF660173C44751C22ADFFB53E9FC669EF628C3CFBBF8F20020000E55487A168C338F1A8F8239E73EA6EC82F6855A644D3DE6CF977F1EBA7A9ED1274380DC1CA5F858812AC5C87F76C257D9F4730A6DE983CFAA40A723E9D8F713925010B02925A47E2AA661DA1893458327AF6E283EDA0B8BE833180FAAD3EB25E7BAC7553181A19FCB48A3AB015485E52F5C8E1144C41EE300A306D8C52CEE69924BC816CD5C78EC63DFE4AB218F528DA5704344E7479B747CB80E4DB7360FBB786A6419FE6E5ED56236852AE8685FBA36CA75D0F823B889B84F045C04D775A8418D8B23774B4712AF69EDEADCAA9C416C71A1545605CEA204116AD399601604B3B680E8324D1F64897F3AA342044BBD6106E3C9492851D6FD201DFCD560C2EF4029DC08AC799E0E24DA1751983122AD0FDB22D06BF22ED1EDA5A11E78E6BAB9BE55D633F176EDA30FC03A7212E3E9F792DA11DFAB03CC82E839E937AFAB0FBFECD9808F60C17D5BC0749E437BF475E50F160427B3B0958A7A6689BAF164E8704463C65F66E34F324267D604623FFE9DC13DE6CAE7D7D7AD38DACE5B5ADB59E7FB77254E111A00016EE774076EF8D8295C171CFE752319962F394D334881A6636DB5BEBAA2EC023066253007D706D149B241D26EE39EC55A674EA5AFD763880753595A0794EF4FB7E7733869F2DC4AC066BA602F15E82D19C58C03DBB2246C9284BB3B6CCD9EC90F40EEA97C3778FF979CE2C386F42A0803051BA639BEEC08A4EFFB5F66680DD5BE5C0E3442037B883E5A174E9AE4DBA8061F8EA1EC44CFFFBF140000000DF07E32BA71553B1B55DAB5ABA3FD79C814AED2BB7483D02978672876F037BBF8F7FB02F75C78EA21A4CC80663856FE35C73218CBB826E5584D29DB9DDFB5B43'
    pkpBlob = blob.DPAPIBlob(bytes.fromhex(sBlob))
    sMK = '4fb5931bb957c8ff5f4ab466aa2db7c0c28acb64fef5b0fcb8e23a0978e8c2c670bf174d1df3b89d5fe659678ecdd6b90c6d03409fc77dd5248ca33037429b72'
    bPIN = hashlib.pbkdf2_hmac('sha256',bytes.fromhex('330037003300380033003500330034'),bytes.fromhex('eaa46676'),10000)
    bPIN = hashlib.sha512(bPIN.hex().upper().encode('utf-16le')).digest()
    #print(bPIN.hex())
    #bPIN = hashlib.sha512(bPIN).digest()
    pkpBlob.decrypt(bytes.fromhex(sMK),entropy=b'xT5rZW5qVVbrvpuA\x00',smartCardSecret=bPIN)
    if pkpBlob.decrypted: print('Worked')
    print(pkpBlob.cleartext.hex())
    '''
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--system', metavar='HIVE', dest='system')
    parser.add_option('--security', metavar='HIVE', dest='security')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    reg = registry.Regedit()
    secrets = reg.get_lsa_secrets(options.security, options.system)
    dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']

    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(options.masterkeydir)
    mkp.addSystemCredential(dpapi_system)
    mkp.try_credential_hash(None, None)

    for root, _, files in os.walk(args[0]):
        for sFile in files:
            filepath = os.path.join(root, sFile)
            with open(filepath, 'rb') as f:
                file_data = f.read()
                sInfo, arrFieldData = parseFile(file_data)
                print('-' * 10 + ' ' + sFile + ' ' + '-' * 10)
                print('-' * 25 + ' ' + sInfo + ' ' + '-' * 25)
                ### Field 2 and 3 are DPAPI Blob
                parseField1(arrFieldData[0])
                ## Private Key Properties should work with static Entropy '6jnkd5J3ZdQDtrsu'
                blobPrivateKeyProperties = arrFieldData[1]
                pkpBlob = blob.DPAPIBlob(blobPrivateKeyProperties)
                mks = mkp.getMasterKeys(pkpBlob.mkguid.encode())
                for mk in mks:
                    if mk.decrypted:
                        pkpBlob.decrypt(mk.get_key(), entropy = b'6jnkd5J3ZdQDtrsu\x00')
                        if pkpBlob.decrypted:
                            print('[+] Private Key Properties decrypted!')
                            parsePrivateKeyProperties(pkpBlob.cleartext.hex(), True)
                
                ## Private Key, we can try, but the entropy is either unknown static or variable (some are 'xT5rZW5qVVbrvpuA')
                blobPrivateKey = arrFieldData[2]
                pkBlob = blob.DPAPIBlob(blobPrivateKey)
                mks = mkp.getMasterKeys(pkBlob.mkguid.encode())
                for mk in mks:
                    if mk.decrypted:
                        pkBlob.decrypt(mk.get_key(), entropy = b'xT5rZW5qVVbrvpuA\x00')
                        if pkBlob.decrypted:
                            print('[+] Private Key decrypted (' + pkBlob.cleartext[:4].decode() + '):')
                            print('    ' + pkBlob.cleartext.hex())
                        else:
                            #print('[-] Entropy unknown for ' + pkBlob.description.decode() + 'in file ' + filepath)
                            print('[-] Entropy unknown for ' + pkBlob.description.decode())
            print('')
    '''
