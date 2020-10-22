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

from Registry import Registry
import dpapick_py3.crypto as crypto
import dpapick_py3.eater as eater


class Regedit(object):
    """This class provides several functions to handle registry extraction stuff.
    """

    def __init__(self):
        self.syskey = None
        self.lsakeys = None
        self.policy = {"major": 0, "minor": 0, "value": 0}
        self.lsa_secrets = {}

    def get_syskey(self, system):
        """Returns the syskey value after decryption from the registry values.
        system argument is the full path to the SYSTEM registry file (usually
        located under %WINDIR%\\system32\\config\\ directory.

        """
        with open(system, 'rb') as f:
            r = Registry.Registry(f)
            cs = r.open('Select').value('Current').value()
            r2 = r.open("ControlSet%03d\\Control\\Lsa" % cs)
            syskey = ''.join([r2.subkey(x)._nkrecord.classname() for x in ('JD', 'Skew1', 'GBG', 'Data')])
        syskey = bytes.fromhex(syskey)
        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
        self.syskey = ''
        for i in range(len(syskey)):
            self.syskey += '{:02x}'.format(syskey[transforms[i]])
        self.syskey = bytes.fromhex(self.syskey)
        return self.syskey

    def get_lsa_key(self, security):
        """Returns and decrypts the LSA secret key for "CurrentControlSet".
        It is stored under Policy\\PolSecretEncryptionKey.

        security is the full path the the SECURITY registry file (usually
        located under %WINDIR%\\system32\\config\\ directory.

        To decrypt the LSA key, syskey is required. Thus you must first call
        self.get_syskey() if it has not been previously done.
        """
        lsakey = ''
        if self.syskey is None:
            raise ValueError('Must provide syskey or call get_syskey() method first')
        with open(security, 'rb') as f:
            r = Registry.Registry(f)
            rev = eater.Eater(r.open("Policy\\PolRevision").value("(default)").value())
            self.policy["minor"] = rev.eat("H")
            self.policy["major"] = rev.eat("H")
            self.policy["value"] = float("%d.%02d" % (self.policy["major"], self.policy["minor"]))
            if self.policy["value"] > 1.09:
                # NT6
                r2 = r.open("Policy\\PolEKList")
                lsakey = r2.value("(default)").value()
            else:
                # NT5
                r2 = r.open("Policy\\PolSecretEncryptionKey")
                lsakey = r2.value("(default)").value()
        rv = None
        if self.policy['value'] > 1.09:
            currentKey, self.lsakeys = crypto.decrypt_lsa_key_nt6(lsakey, self.syskey)
            rv = self.lsakeys[currentKey]['key']
        else:
            self.lsakeys = crypto.decrypt_lsa_key_nt5(lsakey, self.syskey)
            rv = self.lsakeys[1]
        return rv

    def get_lsa_secrets(self, security, system):
        """Retrieves and decrypts LSA secrets from the registry.
        security and system arguments are the full path to the corresponding
        registry files.
        This function automatically calls self.get_syskey() and
        self.get_lsa_key() functions prior to the secrets retrieval.

        Returns a dictionary of secrets.

        """
        self.get_syskey(system)
        currentKey = self.get_lsa_key(security)
        self.lsa_secrets = {}
        with open(security, 'rb') as f:
            r = Registry.Registry(f)
            r2 = r.open('Policy\\Secrets')
            for i in r2.subkeys():
                self.lsa_secrets[i.name()] = {}
                for j in i.subkeys():
                    self.lsa_secrets[i.name()][j.name()] = j.value('(default)').value()
        for k, v in list(self.lsa_secrets.items()):
            for s in ['CurrVal', 'OldVal']:
                if v[s] != b'':
                    if self.policy['value'] > 1.09:
                        # NT6
                        self.lsa_secrets[k][s] = crypto.decrypt_lsa_secret(v[s], self.lsakeys)
                    else:
                        self.lsa_secrets[k][s] = crypto.SystemFunction005(v[s][0xc:], currentKey)
            for s in ['OupdTime', 'CupdTime']:
                #print(int(self.lsa_secrets[k][s].hex(),16))
                #if self.lsa_secrets[k][s] > 0:
                if not self.lsa_secrets[k][s] == b'':
                    t = eater.Eater(self.lsa_secrets[k][s])
                    self.lsa_secrets[k][s] = int((t.eat('Q') / 10000000) - 11644473600)
        #print(self.lsa_secrets)
        return self.lsa_secrets
    
    def getUsername(self, software, sid):
        """Retrieves username from the SOFTWARE registry when given the full user SID
        """
        with open(software, 'rb') as oFile:
            oReg = Registry.Registry(oFile)
            oRegKey = oReg.open('Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}')
            for oKey in oRegKey.subkeys():
                if sid in oKey.name():
                    return oKey.subkey('UserNames').subkeys()[0].name()
        return '<Unknown>'
    '''
    def getUsername(self, sam, rid):
        """Retrieves username from the SAM registry when given the user RID (integer)
        """
        with open(sam, 'rb') as oFile:
            oReg = Registry.Registry(oFile)
            oRegKey = oReg.open("SAM\\Domains\\Account\\Users\\Names")
            for oKey in oRegKey.subkeys():
                if int(oKey.value('(default)').value_type()) == rid: return oKey.name()
        return '<Unknown>'
    '''
# vim:ts=4:expandtab:sw=4

