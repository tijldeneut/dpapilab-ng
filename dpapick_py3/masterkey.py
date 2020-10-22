#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2010, 2011 Cassidian SAS. All rights reserved.            ##
## Copyright (C) 2020       Howest. All rights reserved.                   ##
##                                                                         ##
##  Author:  Jean-Michel Picod <jmichel.p@gmail.com>                       ##
##  Updated: Photubias <tijl.deneut@howest.be>                             ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

import hashlib, os, re, binascii
from collections import defaultdict
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import struct
import dpapick_py3.crypto as crypto
import dpapick_py3.eater as eater
import dpapick_py3.credhist as credhist

class MasterKey(eater.DataStruct):
    """This class represents a MasterKey block contained in a MasterKeyFile"""

    def __init__(self, raw=None):
        self.decrypted = False
        self.key = None
        self.key_hash = None
        self.hmacSalt = None
        self.hmac = None
        self.hmacComputed = None
        self.cipherAlgo = None
        self.hashAlgo = None
        self.rounds = None
        self.iv = None
        self.test = 123
        self.version = None
        self.ciphertext = None
        eater.DataStruct.__init__(self, raw)

    def __getstate__(self):
        d = dict(self.__dict__)
        for k in ["cipherAlgo", "hashAlgo"]:
            if k in d:
                d[k] = d[k].algnum
        return d

    def __setstate__(self, d):
        for k in ["cipherAlgo", "hashAlgo"]:
            if k in d:
                d[k] = crypto.CryptoAlgo(d[k])
        self.__dict__.update(d)

    def parse(self, data):
        self.version = data.eat("L")
        self.iv = data.eat("16s")
        self.rounds = data.eat("L")
        self.hashAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.cipherAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.ciphertext = data.remain()

    def decryptWithHash(self, userSID, pwdhash):
        """Decrypts the masterkey with the given user's hash and SID.
        Simply computes the corresponding key then calls self.decryptWithKey()

        """
        #print("Debug: Inside decryptwithhash. userSID: "+userSID)
        self.decryptWithKey(crypto.derivePwdHash(pwdhash, userSID))

    def decryptWithHash10(self, userSID, pwdhash):
        """Decrypts the masterkey with the given user's hash and SID.
        Simply computes the corresponding key then calls self.decryptWithKey()
        """
        #print("Debug: Inside decryptwithhash10. userSID: "+userSID)
        #print("Debug: Inside decryptwithhash. pwdhash: "+binascii.hexlify(pwdhash))
        pwdhash1 = hashlib.pbkdf2_hmac('sha256', pwdhash, userSID.encode("UTF-16LE"), 10000)
        #print("Debug: Inside decryptwithhash. pwdhash1:"+binascii.hexlify(pwdhash1))
        pwdhash2 = hashlib.pbkdf2_hmac('sha256', pwdhash1, userSID.encode("UTF-16LE"), 1)[0:16]
        #print("Debug: Inside decryptwithhash. pwdhash2:"+binascii.hexlify(pwdhash2))
        
        #print("Debug: Inside decryptwithhash. Derived hash:" + binascii.hexlify(derivedkey))
        self.decryptWithKey(crypto.derivePwdHash(pwdhash2, userSID))

    def decryptWithPassword(self, userSID, pwd):
        """Decrypts the masterkey with the given user's password and SID.
        Simply computes the corresponding key, then calls self.decryptWithKey()

        """
        for algo in ["sha1", "md4"]:
            self.decryptWithKey(crypto.derivePwdHash(hashlib.new(algo, pwd.encode("UTF-16LE")).digest(), userSID))
            if self.decrypted:
                break

    def setKeyHash(self, h):
        assert(len(h) == 20)
        self.decrypted = True
        self.key_hash = h

    def setDecryptedKey(self, data):
        assert len(data) == 64
        self.decrypted = True
        self.key = data
        self.key_hash = hashlib.sha1(data).digest()

    def decryptWithKey(self, pwdhash):
        """Decrypts the masterkey with the given encryption key. This function
        also extracts the HMAC part of the decrypted stuff and compare it with
        the computed one.

        Note that, once successfully decrypted, the masterkey will not be
        decrypted anymore; this function will simply return.

        """
        if self.decrypted:
            return
        if not self.ciphertext:
            return
        # Compute encryption key
        cleartxt = crypto.dataDecrypt(self.cipherAlgo, self.hashAlgo, self.ciphertext,
                                      pwdhash, self.iv, self.rounds)
        self.key = cleartxt[-64:]
        self.hmacSalt = cleartxt[:16]
        self.hmac = cleartxt[16:16 + int(self.hashAlgo.digestLength)]
        self.hmacComputed = crypto.DPAPIHmac(self.hashAlgo, pwdhash, self.hmacSalt, self.key)
        self.decrypted = self.hmac == self.hmacComputed
        if self.decrypted:
            self.key_hash = hashlib.sha1(self.key).digest()

    def __repr__(self):
        s = ["Masterkey block"]
        if self.cipherAlgo is not None:
            s.append("\tcipher algo  = %s" % repr(self.cipherAlgo))
        if self.hashAlgo is not None:
            s.append("\thash algo    = %s" % repr(self.hashAlgo))
        if self.rounds is not None:
            s.append("\trounds       = %i" % self.rounds)
        if self.iv is not None:
            s.append("\tIV           = %s" % self.iv.hex())
        if self.key is not None:
            s.append("\tkey          = %s" % self.key.hex())
        if self.hmacSalt is not None:
            s.append("\thmacSalt     = %s" % self.hmacSalt.hex())
        if self.hmac is not None:
            s.append("\thmac         = %s" % self.hmac.hex())
        if self.hmacComputed is not None:
            s.append("\thmacComputed = %s" % self.hmacComputed.hex())
        if self.key_hash is not None:
            s.append("\tkey hash     = %s" % self.key_hash.hex())
        if self.ciphertext is not None:
            s.append("\tciphertext   = %s" % self.ciphertext.hex())
        return "\n".join(s)


class CredHist(eater.DataStruct):
    """This class represents a Credhist block contained in the MasterKeyFile"""

    def __init__(self, raw=None):
        self.version = None
        self.guid = None
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.guid = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")

    def __repr__(self):
        s = ["CredHist block",
             "\tversion = %d" % self.version,
             "\tguid    = %s" % self.guid]
        return "\n".join(s)


class DomainKey(eater.DataStruct):
    """This class represents a DomainKey block contained in the MasterKeyFile.
    Currently does nothing more than parsing. Work on Active Directory stuff is
    still on progress.
    """
    def __init__(self, raw=None):
        self.version = None
        self.secretLen = None
        self.accesscheckLen = None
        self.guidKey = None
        self.encryptedSecret = None
        self.accessCheck = None
        self.decrypted = False
        self.key = None
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.secretLen = data.eat("L")
        self.accesscheckLen = data.eat("L")
        self.guidKey = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")  #data.eat("16s")
        self.encryptedSecret = data.eat("%us" % self.secretLen)
        self.accessCheck = data.eat("%us" % self.accesscheckLen)

    def __repr__(self):
        s = ["DomainKey block",
             "\tversion     = %x" % self.version,
             "\tguid        = %s" % self.guidKey,
             "\tsecret      = %s" % self.encryptedSecret.hex(),
             "\taccessCheck = %s" % self.accessCheck.hex()]
        return "\n".join(s)

    def decryptWithDCKey(self, dcKeyFile):
        tmpdata = bytearray(self.encryptedSecret); tmpdata.reverse(); revmk=tmpdata
        rsakey = RSA.importKey(open(dcKeyFile, "r").read())
        cipher = PKCS1_v1_5.new(rsakey)
        decrypted_data = cipher.decrypt(binascii.unhexlify(binascii.hexlify(revmk)),0)
        if decrypted_data > 0:
            self.key = decrypted_data[8:72]
            if self.key is not None:
                self.decrypted = True

class MasterKeyFile(eater.DataStruct):
    """This class represents a masterkey file."""

    def __init__(self, raw=None):
        self.masterkey = None
        self.backupkey = None
        self.credhist = None
        self.domainkey = None
        self.decrypted = False
        self.version = None
        self.guid = None
        self.policy = None
        self.masterkeyLen = self.backupkeyLen = self.credhistLen = self.domainkeyLen = 0
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        data.eat("2L")
        self.guid = data.eat("72s").decode("UTF-16LE").encode("utf-8")
        data.eat("2L")
        self.policy = data.eat("L")
        self.masterkeyLen = data.eat("Q")
        self.backupkeyLen = data.eat("Q")
        self.credhistLen = data.eat("Q")
        self.domainkeyLen = data.eat("Q")

        if self.masterkeyLen > 0:
            self.masterkey = MasterKey()
            self.masterkey.parse(data.eat_sub(self.masterkeyLen))
        if self.backupkeyLen > 0:
            self.backupkey = MasterKey()
            self.backupkey.parse(data.eat_sub(self.backupkeyLen))
        if self.credhistLen > 0:
            self.credhist = CredHist()
            self.credhist.parse(data.eat_sub(self.credhistLen))
        if self.domainkeyLen > 0:
            try:
                self.domainkey = DomainKey()
                self.domainkey.parse(data.eat_sub(self.domainkeyLen))
            except:
                print('Error with reading domain Key')
                self.domainkeyLen = 0
                self.domainkey = None

    def decryptWithHash(self, userSID, h, alg='sha1'):
        """See MasterKey.decryptWithHash()"""
        if not self.masterkey.decrypted and alg == 'sha1':
            self.masterkey.decryptWithHash(userSID, h)
        if not self.masterkey.decrypted and alg == 'md4':
            self.masterkey.decryptWithHash(userSID, h)
            if not self.masterkey.decrypted:
                self.masterkey.decryptWithHash10(userSID, h)
        #disabling backup key decrypting for more quickly....
        #if not self.backupkey.decrypted and alg =='sha1':
        #    self.backupkey.decryptWithHash(userSID, h)
        #if not self.backupkey.decrypted and alg=='md4':
        #    self.backupkey.decryptWithHash(userSID, h)
        #    if not self.backupkey.decrypted:
        #        self.backupkey.decryptWithHash10(userSID, h)
        self.decrypted = self.masterkey.decrypted or self.backupkey.decrypted

    def decryptWithPassword(self, userSID, pwd):
        """See MasterKey.decryptWithPassword()"""
        #print "\nDebug: inside decryptWithPassword:"
        for algo in ["sha1", "md4"]:
            #print "Debug: inside decryptWithPassword algo:"+algo
            self.decryptWithHash(userSID, hashlib.new(algo, pwd.encode('UTF-16LE')).digest(), algo)
            
            if self.decrypted:
                break

    def decryptWithKey(self, pwdhash):
        """See MasterKey.decryptWithKey()"""
        if not self.masterkey.decrypted:
            self.masterkey.decryptWithKey(pwdhash)
        if not self.backupkey.decrypted:
            self.backupkey.decryptWithKey(pwdhash)
        self.decrypted = self.masterkey.decrypted or self.backupkey.decrypted

    def addKeyHash(self, guid, h):
        self.guid = guid
        self.masterkey = MasterKey()
        self.backupkey = MasterKey()
        self.masterkey.setKeyHash(h)
        self.decrypted = True

    def addDecryptedKey(self, guid, data):
        self.guid = guid
        self.masterkey = MasterKey()
        self.backupkey = MasterKey()
        self.masterkey.setDecryptedKey(data)
        self.decrypted = True

    def get_key(self):
        """Returns the first decrypted block between Masterkey and BackupKey.
        If none has been decrypted, returns the Masterkey block.
        """
        if self.masterkey.decrypted:
            return self.masterkey.key or self.masterkey.key_hash
        elif self.backupkey.decrypted:
            return self.backupkey.key
        return self.masterkey.key

    def __repr__(self):
        s = ["\n#### MasterKeyFile %s ####" % self.guid.decode()]
        if self.version is not None:
            s.append("\tversion   = %#d" % self.version)
        if self.policy is not None:
            s.append("\tPolicy    = %#x" % self.policy)
        if self.masterkeyLen > 0:
            s.append("\tMasterKey = %d" % self.masterkeyLen)
        if self.backupkeyLen > 0:
            s.append("\tBackupKey = %d" % self.backupkeyLen)
        if self.credhistLen > 0:
            s.append("\tCredHist  = %d" % self.credhistLen)
        if self.domainkeyLen > 0:
            s.append("\tDomainKey = %d" % self.domainkeyLen)
        if self.masterkey:
            s.append("    + Master Key: %s" % repr(self.masterkey))
        if self.backupkey:
            s.append("    + Backup Key: %s" % repr(self.backupkey))
        if self.credhist:
            s.append("    + %s" % repr(self.credhist))
        if self.domainkey:
            s.append("    + %s" % repr(self.domainkey))
        return "\n".join(s)


class MasterKeyPool(object):
    """This class is the pivot for using DPAPIck. It manages all the DPAPI
    structures and contains all the decryption intelligence.
    """

    def __init__(self):
        self.keys = defaultdict(lambda: [])
        self.creds = {}
        self.system = None
        self.passwords = set()

    def addMasterKey(self, mkey):
        """Add a MasterKeyFile is the pool.
        mkey is a string representing the content of the file to add.
        """
        mkf = MasterKeyFile(mkey)
        self.keys[mkf.guid].append(mkf)

    def addMasterKeyHash(self, guid, h):
        self.keys[guid].append(MasterKeyFile().addKeyHash(guid, h))

    def getMasterKeys(self, guid):
        """Returns an array of Masterkeys corresponding the the given GUID.
        """
        return self.keys.get(guid, [])

    def addSystemCredential(self, blob):
        """Adds DPAPI_SYSTEM token to the pool.
        blob is a string representing the LSA secret token
        """
        self.system = credhist.CredSystem(blob)

    def addCredhist(self, sid, cred):
        """Internal use. Adds a CredHistFile to the pool.
        sid is a string representing the user's SID
        cred is CredHistFile object.
        """
        self.creds[sid] = cred

    def addCredhistFile(self, sid, credfile):
        """Adds a Credhist file to the pool.
        sid is a string representing the user's SID
        credfile is the full path to the CREDHIST file to add.
        """
        with open(credfile, 'rb') as f:
            self.addCredhist(sid, credhist.CredHistFile(f.read()))

    def loadDirectory(self, directory):
        """Adds every masterkey contained in the given directory to the pool.
        If a file is not a valid Masterkey file, this function simply goes to
        the next file without complaining.

        directory is a string representing the directory path to add.
        """
        for k in os.listdir(directory):
            if re.match("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", k, re.IGNORECASE):
                try:
                    with open(os.path.join(directory, k), 'rb') as f:
                        self.addMasterKey(f.read())
                except:
                    pass

    def pickle(self, filename=None):
        if filename is not None:
            pickle.dump(self, filename, 2)
        else:
            return pickle.dumps(self, 2)

    def __getstate__(self):
        d = dict(self.__dict__)
        d["keys"] = dict(d["keys"])
        return d

    def __setstate__(self, d):
        tmp = dict(d["keys"])
        d["keys"] = defaultdict(lambda: [])
        d["keys"].update(tmp)
        self.__dict__.update(d)

    @staticmethod
    def unpickle(data=None, filename=None):
        if data is not None:
            return pickle.loads(data)
        if filename is not None:
            return pickle.load(filename)
        raise ValueError("must provide either data or filename argument")

    def try_credential_hash(self, userSID, pwdhash):
        n = 0
        #for mkl in self.keys.values():
        for mkl in list(self.keys.values()):
            for mk in mkl:
                if not mk.decrypted:
                    if pwdhash is not None:
                        mk.decryptWithHash(userSID, pwdhash)
                        if not mk.decrypted and self.creds.get(userSID) is not None:
                            # process CREDHIST
                            self.creds[userSID].decryptWithHash(pwdhash)
                            for cred in self.creds[userSID].entries_list:
                                mk.decryptWithHash(userSID, cred.pwdhash)
                                if cred.ntlm is not None and not mk.decrypted:
                                    mk.decryptWithHash(userSID, cred.ntlm)
                                if mk.decrypted:
                                    self.creds[userSID].validate()
                                    break
                    if not mk.decrypted and self.system is not None:
                        # try DPAPI_SYSTEM creds
                        mk.decryptWithKey(self.system.user)
                        if not mk.decrypted:
                            mk.decryptWithKey(self.system.machine)
                        if userSID is not None and not mk.decrypted:
                            # try with an extra SID (just in case)
                            mk.decryptWithHash(userSID, self.system.user)
                            if not mk.decrypted:
                                mk.decryptWithHash(userSID, self.system.machine)
                    if mk.decrypted:
                        n += 1
        return n

    def try_credential(self, userSID, password):
        """This function tries to decrypt every masterkey contained in the pool
        that has not been successfully decrypted yet with the given password and
        SID.

        userSID is a string representing the user's SID
        password is a string representing the user's password.

        Returns the number of masterkey that has been successfully decrypted
        with those credentials.

        """
        n = 0
        #for mkl in self.keys.values():
        for mkl in list(self.keys.values()):
            for mk in mkl:
                if not mk.decrypted:
                    if password is not None:
                        mk.decryptWithPassword(userSID, password)
                        if not mk.decrypted and self.creds.get(userSID) is not None:
                            # process CREDHIST
                            self.creds[userSID].decryptWithPassword(password)
                            for cred in self.creds[userSID].entries_list:
                                mk.decryptWithHash(userSID, cred.pwdhash)
                                if cred.ntlm is not None and not mk.decrypted:
                                    mk.decryptWithHash(userSID, cred.ntlm)
                                if mk.decrypted:
                                    self.creds[userSID].validate()
                                    break
                    if not mk.decrypted and self.system is not None:
                        # try DPAPI_SYSTEM creds
                        mk.decryptWithHash(userSID, self.system.user)
                        if not mk.decrypted:
                            mk.decryptWithHash(userSID, self.system.machine)
                        if not mk.decrypted:
                            mk.decryptWithKey(self.system.user)
                        if not mk.decrypted:
                            mk.decryptWithKey(self.system.machine)
                    if mk.decrypted:
                        self.passwords.add(password)
                        n += 1
        return n

    def try_domain(self, privkeyfile):
        """
        try to decrypt domain backup key with DC RSA private key
        """
        n = 0
        #for mkl in self.keys.values():
        for mkl in list(self.keys.values()):
            for mk in mkl:
                if not mk.decrypted:
                    mk.domainkey.decryptWithDCKey(privkeyfile)
                    if mk.domainkey.decrypted:
                        mk.decrypted = True
                        mk.masterkey.key = mk.domainkey.key

                    if mk.decrypted:
                        n += 1
        return n        


    def __repr__(self):
        #s = ['MasterKeyPool:', 'Passwords:', repr(self.passwords), 'Keys:', repr(self.keys.items())]
        s = ['MasterKeyPool:', 'Passwords:', repr(self.passwords), 'Keys:', repr(list(self.keys.items()))]
        if self.system is not None:
            s.append(repr(self.system))
        s.append("CredHist entries:")
        #for i in self.creds.keys():
        for i in list(self.creds.keys()):
            s.append("\tSID: %s" % i)
            s.append(repr(self.creds[i]))
        return "\n".join(s)

# vim:ts=4:expandtab:sw=4
