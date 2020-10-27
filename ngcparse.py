#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2020, Tijl "Photubias" Deneut <tijl.deneut@howest.be>

import optparse, os, sys, time

def check_parameters(options, args):
    if not args or len(args) != 1:
        sys.exit('You must provide an NGC folder.')

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def parseTimestamp(bData):
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

def main(sNGCFolder, boolOutput = True):
    arrGUIDs = os.listdir(sNGCFolder)
    arrResult = []
    for sGUID in arrGUIDs:
        with open(os.path.join(sNGCFolder, sGUID, '1.dat'), 'rb') as f: sUserSID = f.read().decode('UTF16')
        try: 
            with open(os.path.join(sNGCFolder, sGUID, '7.dat'), 'rb') as f: sMainProvider = f.read().decode('UTF16')
        except: 
            exit('[-] Failed, are you running as System? (not Admin)')
        
        if boolOutput:
            print('[+] NGC GUID      : ' + sGUID)
            print('[+] User SID      : ' + sUserSID)
            print('[+] Main Provider : ' + sMainProvider)
        
            print('\n== Protectors ==')
        
        arrNGCData = (sGUID, sUserSID, sMainProvider)
        arrProtectors = parseProtectors(os.path.join(sNGCFolder, sGUID, 'Protectors'), boolOutput)

        if boolOutput: print('== Items ==')
        arrItems = parseItems(os.path.join(sNGCFolder, sGUID), boolOutput)
        arrResult.append((arrNGCData, arrProtectors, arrItems))
        if boolOutput: print('=' * 50)
    
    
    ## Optionally print stuff needed for NGC Windows Hello PIN DECRYPT
    
    bInputData = b''
    sGUID1 = ''
    for arrProtector in arrProtectors:
        if arrProtector[1] == 'Microsoft Software Key Storage Provider' or 'Microsoft Platform Crypto Provider': 
            sGUID1 = arrProtector[2]
            bInputData = arrProtector[4]
    for arrItem in arrItems:
        if arrItem[1] == '//9DDC52DB-DC02-4A8C-B892-38DEF4FA748F': sGUID2 = arrItem[3]
    if boolOutput: 
        if sGUID1 == '':
            print('[+] MS Platform Crypto Provider, in TPM!')
        else:
            print('[+] MS Key Storage Provider GUID1 : ' + sGUID1)
        print('[+] With InputData (' + str(len(bInputData)) + ' bytes)    : ' + bInputData.hex())
        print('[+] MS Key Storage Provider GUID2 : ' + sGUID2)
        
    return arrResult

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog ngc_folder\n\n'
        'It tries to parse a system NGC Folder.\n'
        '\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\n'
        'Watch out: Folder path above requires SYSTEM privileges')

    parser = optparse.OptionParser(usage=usage)
    
    (options, args) = parser.parse_args()
    check_parameters(options, args)
   
    main(args[0])
    
