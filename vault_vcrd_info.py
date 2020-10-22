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
"""VAULT VCRD file info."""

import construct, optparse, os, sys, vaultstruct

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or len(args) != 1:
        sys.exit('You must provide a vault VCRD file.')
    elif not os.path.isfile(args[0]):
        sys.exit('You must provide a vault VCRD readable file.')


if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog vault_vcrd_file\n\n'
        'It tries to parse a Vault VCRD file.')

    parser = optparse.OptionParser(usage=usage)

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    vcrd_filename = args[0]
    #with open(vcrd_filename, 'rb') as fin: print(fin.read().hex())
    with open(vcrd_filename, 'rb') as fin:
        vcrd = vaultstruct.VAULT_VCRD.parse(fin.read())
        print(vcrd)
