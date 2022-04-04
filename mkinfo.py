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
""" Windows DPAPI MasterKey info report."""

import optparse, os, sys

try:
    from dpapick3 import masterkey
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')


def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or not len(args) == 1:
        sys.exit('You must provide an argument.')

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [*no-options*] MK-file|MK-directory\n\n'
        'It tries to parse the input file or directory and it reports '
        'MasterKey files properties. You can use a single file as argument '
        'or a directory.')

    parser = optparse.OptionParser(usage=usage)
    (options, args) = parser.parse_args()

    check_parameters(options, args)

    if os.path.isfile(args[0]):
        with open(args[0], 'rb') as mkf:
            try:
                mk = masterkey.MasterKeyFile(mkf.read())
                print(mk)
            except:
                print('\nMasterKey parsing failure! See next details.\n')
                raise
    elif os.path.isdir(args[0]):
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(args[0])
        print(mkp)
    else:
        print('Argument is not a file nor a directory.')
