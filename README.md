# Windows DPAPI-NG lab in Python 3

Forked from https://github.com/dfirfpi/dpapilab
 with every single file edited and several additions

Here I want to put some ongoing work that involve 
Windows DPAPI (Data Protection API). 
It's a lab, so something may not work: 
please see "How to Use" and ask questions.

## How to install
Prerequisites:  
```
sudo apt update && sudo apt install -y python3-pip git  
python3 -m pip install wheel pytz pycryptodome python-registry dpapick3 construct==2.5.5-reupload #--use-deprecated=legacy-resolver
```

The construct package is only needed for creddec.py & vaultdec.py (but not for ngcvaultdec.py) and on Windows requires the `--use-deprecated=legacy-resolver` option

The DPAPI bulk of the work is done by DPAPICK3 (https://pypi.org/project/dpapick3/)

Installing permanently (Linux):  
```
git clone https://github.com/tijldeneut/dpapilab-ng  
cd dpapilab-ng  
sudo python3 -m pip install -r requirements.txt
sudo cp -rp *.py /usr/bin/
```

Oneliner for Linux:  
```
git clone https://github.com/tijldeneut/dpapilab-ng && cd dpapilab-ng && sudo python3 -m pip install -r requirements.txt && chmod a+x *.py && sudo cp -rp *.py /usr/bin/ && cd .. && sudo rm -rf dpapilab-ng
```

Installation (Windows):  
First install the latest version of Python3.  
```
powershell iwr https://github.com/tijldeneut/dpapilab-ng/archive/refs/heads/main.zip -O dpapilabng.zip  
powershell expand-archive dpapilabng.zip ; cd dpapilabng\dpapilab-ng-main  
python -m pip install -r requirements.txt
```

Feel free to add the current path to the Windows Path environment variable for global use.

## How to use


Every utility has usually a minimal description that should help its usage.
Please consider that this is a *laboratory*, so don't expect that everything
will work: there are experiments and messy stuffs here. Usually I create a
brief description (as the followings) for those utilities that are completed.

In any case feel free to open a bug or a request. Any contribution is much 
appreciated.

The dpapick dependency for Python3 has recently been published,
this is from https://github.com/mis-team/dpapick, 
but, again, every file changed to accomodate for using Python3.

- **blobinfo.py**: this small utility simply tries to parse a DPAPI BLOB file.
- **blobdec.py**: this utility tries to decrypt a *system* or *user* DPAPI BLOB file provided, using DPAPI system key stored in LSA secrets or user password/hash.
- **blobdec-with-masterkey.py**: this utility tries to decrypt a DPAPI BLOB given an already unlocked MasterKey (hex format) and an optional entropy.
- **mkinfo.py**: this small utility simply tries to parse a MasterKey file or a directory containing MasterKey files.
- **mkdecs.py**: this utility tries to decrypt the *system* MasterKey files provided, using DPAPI system key stored in LSA secrets.
- **mkdecu.py**: this utility tries to decrypt the *user* MasterKey files provided, using the user password, password hash or Domain PVK file.
- **winwifidec.py**: this utility (formerly called wiffy.py) decrypts Windows Wi-Fi password, which are (usually) system wide.  
To decrypt them you need: the DPAPI system key, which is one of the OS LSA secrets;  
the system MasterKeys, stored in ``\Windows\System32\Microsoft\Protect\S-1-5-18\User``;  
and the WiFi directory, ``\ProgramData\Microsoft\WwanSvc\Profiles``.
- **winwifipeapdec.py**: this utility decrypts Windows Wi-Fi Enterprise passwords, these are first encrypted using system Masterkeys,  
but the password itself is in ``NTUSER.dat`` and encrypted with user Masterkeys, so both are needed.
- **browserdec.py**: this utility tries to decrypt both cookies and stored browser passwords from either Chrome, Opera or the newer MS Edge browser.  
Using many different ways (masterkeys, SHA1/NT hashes or AD PVK file) 
- **creddec.py**: this utility tries to decrypt Windows Credential files 
- **crypokeysdec.py**: this utility tries to decrypt Windows Crypto files
- **vaultdec.py**: this utility tries to decrypt Windows Vault files
- **openvpndec.py**: this utility tries to decrypt OpenVPN certificate passphrases that are stored in ``NTUSER.dat`` and encrypted with the User MasterKey

The NGC files are accompanied by an article, read it here: 
https://www.insecurity.be/blog/2020/12/24/dpapi-in-depth-with-tooling-standalone-dpapi/

## NGC Usage

- **ngcparse.py**: parses the Windows Ngc folder and files:  
  ``\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc``  
  On a live system, this requires SYSTEM privileges
- **ngcvaultdec.py**: similar to ***vaultdec.py*** but adds a parsing layer
- **ngcregistrydec.py**: parses the ``SOFTWARE`` to parse the NgcPin data  
Successful output is ***EncData***, ***IV*** and ***EncPassword***
- **ngccryptokeysdec.py**: parses and decrypts the RSA/ECDS keys in  
``\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys``  
using the System MasterKey.  
Also implements ***ncrypt.dll*** functionality to decrypt the Private Keys using a PIN (***smartCardSecret***) and brute force PINs
- **_ngc_step_by_step_on_and_offline.py**: fully decrypt an encrypted Windows  
Hello Ngc PIN credential by running the other scripts manually.  
Use this script to learn to use the other scripts, requires other scripts
- **_ngc_full_auto.py**: tries to fully automatically decrypt Windows Hello Ngc Pins by calling the other scripts, only needs a Windows folder.  
Use this script for a quick win, requires other scripts

## Licensing and Copyright

Copyright 2015 Francesco "dfirfpi" Picasso. All Rights Reserved.  
Copyright 2022 Tijl "Photubias" Deneut. All Rights Reserved.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.

## Bugs and Support

There is no support provided with this software. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.

For any bug or enhancement please use this site facilities.
