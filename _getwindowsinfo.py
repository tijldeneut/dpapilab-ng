#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
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
'''
Decrypting and parsing some interesting and General Windows Information.
Offline and based on certain files and/or registry dumps
'''
import optparse, os
## requires python3 -m pip install python-registry
from Registry.Registry import Registry

## Source: https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
dictNormalGroups = {'S-1-0-0':'Nobody', 'S-1-1':'World Authority', 'S-1-1-0':'Everyone', 'S-1-2':'Local Authority', 'S-1-2-0':'Local', 'S-1-2-1':'Console Logon', 'S-1-3':'Creator Authority', 'S-1-3-0':'Creator Owner', 'S-1-3-1':'Creator Group', 'S-1-3-2':'Creator Owner Server', 'S-1-3-3':'Creator Group Server', 'S-1-3-4':'Owner Rights', 'S-1-4':'Non-unique Authority', 'S-1-5':'NT Authority', 'S-1-5-1':'Dialup', 'S-1-5-10':'Principal Self', 'S-1-5-11':'Authenticated Users', 'S-1-5-12':'Restricted Code', 'S-1-5-13':'Terminal Server Users', 'S-1-5-14':'Remote Interactive Logon', 'S-1-5-15':'This Organization', 'S-1-5-17':'This Organization', 'S-1-5-18':'Local System', 'S-1-5-19':'NT Authority', 'S-1-5-2':'Network', 'S-1-5-20':'NT Authority', 'S-1-5-3':'Batch', 'S-1-5-4':'Interactive', 'S-1-5-6':'Service', 'S-1-5-7':'Anonymous', 'S-1-5-8':'Proxy', 'S-1-5-9':'Enterprise Domain Controllers'}
dictDomainGroups = {'496':'COMPOUNDED_AUTHENTICATION', '497':'CLAIMS_VALID', '498':'Enterprise Read-only Domain Controllers', '500':'Administrator', '501':'Guest', '502':'KRBTGT', '512':'Domain Admins', '513':'Domain Users', '514':'Domain Guests', '515':'Domain Computers', '516':'Domain Controllers', '517':'Cert Publishers', '518':'Schema Admins', '519':'Enterprise Admins', '520':'Group Policy Creator Owners', '521':'Read-only Domain Controllers', '522':'Cloneable Domain Controllers', '525':'PROTECTED_USERS', '526':'Key Admins', '527':'Enterprise Key Admins', '553':'RAS and IAS Servers', '571':'Allowed RODC Password Replication Group', '572':'Denied RODC Password Replication Group'}
dictBuiltinGroups = {'S-1-15-2-1':'ALL_APP_PACKAGES', 'S-1-16-0':'Untrusted Mandatory Level', 'S-1-16-12288':'High Mandatory Level', 'S-1-16-16384':'System Mandatory Level', 'S-1-16-20480':'Protected Process Mandatory Level', 'S-1-16-28672':'Secure Process Mandatory Level', 'S-1-16-4096':'Low Mandatory Level', 'S-1-16-8192':'Medium Mandatory Level', 'S-1-16-8448':'Medium Plus Mandatory Level', 'S-1-18-1':'AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY', 'S-1-18-2':'SERVICE_ASSERTED_IDENTITY', 'S-1-18-3':'FRESH_PUBLIC_KEY_IDENTITY', 'S-1-18-4':'KEY_TRUST_IDENTITY', 'S-1-18-5':'KEY_PROPERTY_MFA', 'S-1-18-6':'KEY_PROPERTY_ATTESTATION', 'S-1-5-1000':'OTHER_ORGANIZATION', 'S-1-5-113':'LOCAL_ACCOUNT', 'S-1-5-114':'LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP', 'S-1-5-32-544':'Administrators', 'S-1-5-32-545':'Users', 'S-1-5-32-546':'Guests', 'S-1-5-32-547':'Power Users', 'S-1-5-32-548':'Account Operators', 'S-1-5-32-549':'Server Operators', 'S-1-5-32-550':'Print Operators', 'S-1-5-32-551':'Backup Operators', 'S-1-5-32-552':'Replicators', 'S-1-5-32-554':r'Builtin\Pre-Windows 2000 Compatible Access', 'S-1-5-32-555':r'Builtin\Remote Desktop Users', 'S-1-5-32-556':r'Builtin\Network Configuration Operators', 'S-1-5-32-557':r'Builtin\Incoming Forest Trust Builders', 'S-1-5-32-558':r'Builtin\Performance Monitor Users', 'S-1-5-32-559':r'Builtin\Performance Log Users', 'S-1-5-32-560':r'Builtin\Windows Authorization Access Group', 'S-1-5-32-561':r'Builtin\Terminal Server License Servers', 'S-1-5-32-562':r'Builtin\Distributed COM Users', 'S-1-5-32-568':'IIS_IUSRS', 'S-1-5-32-569':r'Builtin\Cryptographic Operators', 'S-1-5-32-573':r'Builtin\Event Log Readers', 'S-1-5-32-574':r'Builtin\Certificate Service DCOM Access', 'S-1-5-32-575':r'Builtin\RDS Remote Access Servers', 'S-1-5-32-576':r'Builtin\RDS Endpoint Servers', 'S-1-5-32-577':r'Builtin\RDS Management Servers', 'S-1-5-32-578':r'Builtin\Hyper-V Administrators', 'S-1-5-32-579':r'Builtin\Access Control Assistance Operators', 'S-1-5-32-580':r'Builtin\Remote Management Users', 'S-1-5-32-582':'Storage Replica Administrators', 'S-1-5-33':'WRITE_RESTRICTED_CODE', 'S-1-5-64-10':'NTLM Authentication', 'S-1-5-64-14':'SChannel Authentication', 'S-1-5-64-21':'Digest Authentication', 'S-1-5-65-1':'THIS_ORGANIZATION_CERTIFICATE', 'S-1-5-80':'NT Service', 'S-1-5-80-0':r'NT Services\All Services', 'S-1-5-80-0':'All Services', 'S-1-5-83-0':r'NT Virtual Machine\Virtual Machines', 'S-1-5-84-0-0-0-0-0':'USER_MODE_DRIVERS', 'S-1-5-90-0':r'Windows Manager\Windows Manager Group'}
dictAllGroups = {**dictNormalGroups, **dictDomainGroups, **dictBuiltinGroups}
## There also "meta group id's": https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab

def check_parameters(options, args):
    if options.live: return
    if not args or len(args) != 4:
        exit('[-] Cannot parse anything without any hives.')

def getHostname(sSOFTWARE, boolVerbose = False):
    with open(sSOFTWARE, 'rb') as oFile:
        oReg = Registry(oFile)
        oKey = oReg.open(r'Microsoft\Windows\CurrentVersion\Group Policy\DataStore\Machine\0')
        sHostname = oKey.value('szTargetName').value()
        if boolVerbose: print('[+] Windows Hostname : ' + sHostname)
        return sHostname

def getLocalUsers(sSOFTWARE, boolMembership = True, boolVerbose = False):
    with open(sSOFTWARE, 'rb') as oFile:
        oReg = Registry(oFile)
        oKey = oReg.open(r'Microsoft\Windows\CurrentVersion\Group Policy\DataStore')
        arrUsers = []
        for oSubKey in oKey.subkeys():
            if oSubKey.name() == 'Machine': continue
            sSID = oSubKey.name()
            if sSID[-5:] == '-1000': continue ## Guest user (defaultuser0), mostly inactive
            sUsername = oSubKey.subkey('0').value('szTargetName').value()
            sDomainSID = sSID.split('-')[4] + '-' + sSID.split('-')[5] + '-' + sSID.split('-')[6]
            if boolVerbose: print(f'[+] Found user {sUsername} with SID {sSID}')
            if boolMembership:
                arrGroups = getLocalGroupMembership(sSOFTWARE, sSID, sDomainSID, boolVerbose)
                arrUsers.append((sSID,sUsername,arrGroups))
            else:
                arrUsers.append((sSID,sUsername))
        return arrUsers

def getLocalGroupMembership(sSOFTWARE, sSID, sDomainSID, boolVerbose = False):
    with open(sSOFTWARE, 'rb') as oFile:
        oReg = Registry(oFile)
        oKey = oReg.open(rf'Microsoft\Windows\CurrentVersion\Group Policy\{sSID}')
        arrGroups = []
        for oValue in oKey.subkey('GroupMembership').values():
            if oValue.name() == 'Count': continue
            sGroupID = oValue.value()
            if sGroupID[:8] == 'S-1-5-21': sGroupID = sGroupID.split('-')[len(sGroupID.split('-'))-1]
            try: sGroup = dictAllGroups[sGroupID]
            except: sGroup = oValue.value()
            arrGroups.append((oValue.value(),sGroup))
            if boolVerbose: print(f'[+]   Member of : {sGroup}')
        return arrGroups

def getSecretQuestions(sSAM, boolVerbose = False): ## These could also be in system / security in older versions of Windows? (lsadump.py on officehustler client)
    with open(sSAM, 'rb') as oFile:
        oReg = Registry(oFile)
        oKey = oReg.open(r'SAM\Domains\Account\Users')
        dictUsers = {}
        for oSubKey in oKey.subkey('Names').subkeys():
            sName = oSubKey.name()
            sRID = str(oSubKey.value('(default)').value_type())
            dictUsers[sRID] = sName
            #if boolVerbose: print(f'[+] User {sName} has RID {sRID}')
        for oSubKey in oKey.subkeys():
            if oSubKey.name() == 'Names': continue
            sRID = str(int(oSubKey.name(),16))
            try:
                bSecretData = oSubKey.value('ResetData').value()
                sUsername = dictUsers[sRID]
                if len(bSecretData) == 56:
                    if boolVerbose: print(f'[-] User {sUsername} has no secret questions')
                    continue
                else:
                    bJsonQuestions = bSecretData.decode('utf-16le')
                    arrQuestionTemp = bJsonQuestions.split('"question":"')
                    arrAnswerTemp = bJsonQuestions.split('"answer":"')
                    arrQuestions = []
                    for i in range (1,len(arrQuestionTemp)):
                        sQuestion = arrQuestionTemp[i].split('"')[0]
                        sAnswer = arrAnswerTemp[i].split('"')[0]
                        arrQuestions.append((sQuestion,sAnswer))
                        if boolVerbose: print(f'[+] User {sUsername}; question {i}: {sQuestion}  -  {sAnswer}')
            except: continue

def getAutoLoginCreds(sSOFTWARE, boolVerbose = False):
    with open(sSOFTWARE, 'rb') as oFile:
        oReg = Registry(oFile)
        oKey = oReg.open(r'Microsoft\Windows NT\CurrentVersion\Winlogon')
        sUsername = sPassword = sDomain = ''
        try: sUsername = oKey.value('DefaultUserName').value()
        except: pass
        try: sPassword = oKey.value('DefaultPassword').value()
        except: pass
        try: sDomain = oKey.value('DefaultDomainName').value()
        except: pass
        if boolVerbose: print(f'[+] Auto Logon found for user {sDomain}\{sUsername} with password {sPassword}')
    return

if __name__ == '__main__':
    usage = (
        'usage: %prog SOFTWARE SECURITY SYSTEM SAM\n\n'
        'It tries to decrypt certain data from registry hives.\n')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--live', metavar='BOOL', dest='live', help='REG SAVE to local folder, run as Administrator')
    
    (options, args) = parser.parse_args()

    check_parameters(options, args)

    if options.live:
        os.system('REG SAVE HKLM\SYSTEM SYSTEM /Y >nul 2>&1')
        os.system('REG SAVE HKLM\SECURITY SECURITY /Y >nul 2>&1')
        os.system('REG SAVE HKLM\SOFTWARE SOFTWARE /Y >nul 2>&1')
        os.system('REG SAVE HKLM\SAM SAM /Y >nul 2>&1')
        sSOFTWAREhive = 'SOFTWARE'
        sSECURITYhive = 'SECURITY'
        sSYSTEMhive = 'SYSTEM'
        sSAMhive = 'SAM'
    else:
        sSOFTWAREhive = args[0]
        sSECURITYhive = args[1]
        sSYSTEMhive = args[2]
        sSAMhive = args[3]
    
    print('#'*10+' Hostname '+'#'*10)
    getHostname(sSOFTWAREhive, True)
    print('#'*10+' Local Users '+'#'*10)
    getLocalUsers(sSOFTWAREhive, True, True)
    print('#'*10+' Secret Questions '+'#'*10)
    getSecretQuestions(sSAMhive, True)
    print('#'*10+' Windows Auto Logon '+'#'*10)
    getAutoLoginCreds(sSOFTWAREhive, True)
