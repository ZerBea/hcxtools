#!/usr/bin/env python2
'''
greps inside hccapx/pmkid structs by essid, mac_ap or mac_sta

This software is Copyright (c) 2019-2020, Alex Stanev <alex at stanev.org> and it is
hereby released to the general public under the following terms:

Redistribution and use in source and binary forms, with or without
modification, are permitted.
'''

from __future__ import print_function
import argparse
import os
import sys
import binascii
import struct
import re
import sre_constants

try:
    from string import maketrans
except ImportError:
    maketrans = bytearray.maketrans  # pylint: disable=no-member

def parse_hccapx(hccapx):
    '''hccapx decompose

    https://hashcat.net/wiki/doku.php?id=hccapx
    struct hccapx
    {
      u32 signature;
      u32 version;
      u8  message_pair;
      u8  essid_len;
      u8  essid[32];
      u8  keyver;
      u8  keymic[16];
      u8  mac_ap[6];
      u8  nonce_ap[32];
      u8  mac_sta[6];
      u8  nonce_sta[32];
      u16 eapol_len;
      u8  eapol[256];

    } __attribute__((packed));
    '''

    hccapx_fmt = '< 4x 4x B B 32s B 16s 6s 32s 6s 32s H 256s'

    try:
        (message_pair,
         essid_len, essid,
         keyver, keymic,
         mac_ap, nonce_ap, mac_sta, nonce_sta,
         eapol_len, eapol) = struct.unpack(hccapx_fmt, hccapx)
    except struct.error as ex:
        sys.stderr.write(str(ex + '\n'))
        exit(1)

    # fixup
    res = ''
    if args.t == 'essid':
        res = essid[:essid_len]
    elif args.t == 'mac_ap':
        res = binascii.hexlify(mac_ap).zfill(12)
    elif args.t == 'mac_sta':
        res = binascii.hexlify(mac_sta).zfill(12)

    return res

def parse_pmkid(pmkid):
    '''pmkid decompose

    format:
        pmkid*mac_ap*mac_sta*essid
    '''

    arr = pmkid.split(b'*', 4)
    res = ''
    if len(arr) == 4:
        try:
            if args.t == 'essid':
                res = binascii.unhexlify(arr[3].strip())
            elif args.t == 'mac_ap':
                res = arr[1]
            elif args.t == 'mac_sta':
                res = arr[2]
        except TypeError as ex:
            sys.stderr.write(str(ex + '\n'))
            exit(1)

    return res

def parse_combined(hashline):
    '''m22000 hashline decompose

    format:
        SIGNATURE*TYPE*PMKID/MIC*MACAP*MACSTA*ESSID*ANONCE*EAPOL*MESSAGEPAIR
    '''

    arr = hashline.split(b'*', 9)
    res = ''
    if len(arr) == 9:
        try:
            if args.t == 'essid':
                res = binascii.unhexlify(arr[5].strip())
            elif args.t == 'mac_ap':
                res = arr[3]
            elif args.t == 'mac_sta':
                res = arr[4]
        except TypeError as ex:
            sys.stderr.write(str(ex + '\n'))
            exit(1)

    return res

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Extract records from wpa combined hashline/hccapx/pmkid file based on regexp')
    #group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument(
        '-f', '--file', type=argparse.FileType('r'),
        help='Obtain patterns from FILE, one per line.')
    parser.add_argument(
        'PATTERNS', type=str, nargs='?',
        help='RegExp pattern')

    parser.add_argument(
        '-v', '--invert-match', dest='v', action='store_true',
        help='Invert the sense of matching, to select non-matching nets')
    parser.add_argument(
        '-t', '--type', dest='t', choices=['essid','mac_ap','mac_sta'], default='essid',
        help='Field to apply matching, default essid')
    parser.add_argument(
        'infile', type=str, nargs='?',
        help='hccapx/pmkid file to process')

    try:
        args = parser.parse_args()
    except IOError as ex:
        parser.error(str(ex))

    # workaround encoding issues with python2
    if sys.version_info[0] == 2:
        reload(sys)                         # pylint: disable=undefined-variable
        sys.setdefaultencoding('utf-8')     # pylint: disable=no-member

    # shift parameters
    if args.file and args.PATTERNS:
        args.infile = args.PATTERNS
        args.PATTERNS = None

    # no patterns set
    if args.PATTERNS is None and args.file is None:
        parser.print_help(sys.stderr)
        sys.stderr.write('You must provide PATTERNS or -f FILE\n')
        exit(1)

    # read patterns from file
    if args.PATTERNS is None:
        args.PATTERNS = '|'.join('(?:{0})'.format(x.strip()) for x in args.file)

    try:
        regexp = re.compile(args.PATTERNS)
    except sre_constants.error as e:
        sys.stderr.write('Wrong regexp {0}: {1} \n'.format(args.PATTERNS, e))
        exit(1)

    if args.infile is not None and os.path.isfile(args.infile):
        fd = open(args.infile, 'rb')
    else:
        fd = sys.stdin
    
    structformat = ''
    while True:
        buf = fd.read(4)
        if buf == 'WPA*':
            buf = buf + fd.readline()
            structformat = 'combined'
        elif buf == 'HCPX':
            buf = buf + fd.read(393 - 4)
            structformat = 'hccapx'
        else:
            buf = buf + fd.readline()
            structformat = 'pmkid'

        if not buf:
            break

        if structformat == 'combined':
            target = parse_combined(buf)
        elif structformat == 'hccapx':
            target = parse_hccapx(buf)
        elif structformat == 'pmkid':
            target = parse_pmkid(buf)
        else:
            sys.stderr.write('Unrecognized input format\n')
            exit(1)

        res = regexp.search(str(target))
        if (res is not None and not args.v) or (res is None and args.v):
            sys.stdout.write(buf)

