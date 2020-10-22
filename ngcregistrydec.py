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
r'''
Credential Providers in the Registry: SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers (with {D6886603-9D2F-4EB2-B667-1971041FA96B} having GUIDs)
'''

import optparse
from Registry.Registry import Registry

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or len(args) != 1:
        exit('[-] Cannot parse anything without SOFTWARE hive.')

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

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

def main(sSOFTWARE, boolOutput = True):
    with open(sSOFTWARE, 'rb') as oFile:
        oReg = Registry(oFile)
        oKey = oReg.open('Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI\\NgcPin\\Credentials')
        arrSIDs = []
        for oSubKey in oKey.subkeys():
            sSID = oSubKey.name()
            bData = oSubKey.value('EncryptedPassword').value()
            arrSIDs.append((sSID, bData))

        if boolOutput: print('[+] Found ' + str(len(arrSIDs)) + ' stored NgcPin Password(s) in the registry :\n')
        oKey = oReg.open('Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}')
        arrUsers = []
        for oSubKey in oKey.subkeys():
            for oItem in arrSIDs:
                if oItem[0] == oSubKey.name():
                    sUsername = oSubKey.subkey('UserNames').subkeys()[0].name()
                    if boolOutput:
                        print('[+] SID         : ' + oItem[0])
                        print('[+] Username    : ' + sUsername)
                    arrUserData = parseFinalData(oItem[1], boolOutput)
                    arrUsers.append((oItem[0], sUsername, arrUserData))
                    if boolOutput: print('=' * 20)
    return arrUsers

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog SOFTWARE_hive\n\n'
        'It tries to decrypt Parse NgcPin from SOFTWARE Registry.\n'
        'Needs the software hive: \n')

    parser = optparse.OptionParser(usage=usage)
    #parser.add_option('--software', metavar='HIVE', dest='software')
    
    (options, args) = parser.parse_args()

    check_parameters(options, args)

    main(args[0])
