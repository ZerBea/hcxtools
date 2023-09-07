#!/usr/bin/env python3
'''
greps inside hccapx/pmkid structs by essid, mac_ap or mac_sta

This software is Copyright (c) 2019-2023, Alex Stanev <alex at stanev.org>
and it is hereby released to the general public under the following terms:

Redistribution and use in source and binary forms, with or without
modification, are permitted.
'''

import argparse
import os
import sys
import binascii
import struct
import re

maketrans = bytearray.maketrans


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

    hccapx_fmt = '< 4x 4x x B 32s x 16x 6s 32x 6s 32x 2x 256x'

    try:
        (essid_len, essid,
         mac_ap, mac_sta) = struct.unpack(hccapx_fmt, hccapx)
    except struct.error:
        sys.stderr.write('Can\'t parse hcccapx struct!\n')
        sys.exit(1)

    # fixup
    if args.t == 'essid':
        return essid[:essid_len]
    if args.t == 'mac_ap':
        return binascii.hexlify(mac_ap).zfill(12)
    if args.t == 'mac_sta':
        return binascii.hexlify(mac_sta).zfill(12)

    return None


def parse_pmkid(pmkid):
    '''pmkid decompose

    format:
        pmkid*mac_ap*mac_sta*essid
    '''

    arr = pmkid.split(b'*', 4)
    if len(arr) == 4:
        try:
            if args.t == 'essid':
                return binascii.unhexlify(arr[3].strip())
            if args.t == 'mac_ap':
                return arr[1]
            if args.t == 'mac_sta':
                return arr[2]
        except TypeError:
            sys.stderr.write('Can\'t decode: {}\n'.format(arr[3].strip().decode()))
            sys.exit(1)

    return None


def parse_combined(hashline):
    '''m22000 hashline decompose

    format:
        SIGNATURE*TYPE*PMKID/MIC*MACAP*MACSTA*ESSID*ANONCE*EAPOL*MESSAGEPAIR
    '''

    arr = hashline.split(b'*', 9)
    if len(arr) == 9:
        try:
            if args.t == 'essid':
                return binascii.unhexlify(arr[5].strip())
            if args.t == 'mac_ap':
                return arr[3]
            if args.t == 'mac_sta':
                return arr[4]
        except TypeError:
            sys.stderr.write('Can\'t decode: {}\n'.format(arr[5].strip().decode()))
            sys.exit(1)

    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Extract records from m22000 hashline/hccapx/pmkid file with regexp')
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
        '-t', '--type', dest='t',
        choices=['essid', 'mac_ap', 'mac_sta'], default='essid',
        help='Field to apply matching, default essid')
    parser.add_argument(
        'infile', type=str, nargs='?',
        help='hccapx/pmkid file to process')

    try:
        args = parser.parse_args()
    except IOError as ex:
        parser.error(str(ex))

    # shift parameters
    if args.file and args.PATTERNS:
        args.infile = args.PATTERNS
        args.PATTERNS = None

    # no patterns set
    if args.PATTERNS is None and args.file is None:
        parser.print_help(sys.stderr)
        sys.stderr.write('You must provide PATTERNS or -f FILE\n')
        sys.exit(1)

    # read patterns from file
    if args.PATTERNS is None:
        args.PATTERNS = '|'.join('(?:{0})'.format(x.strip()) for x in args.file)

    try:
        regexp = re.compile(bytes(args.PATTERNS, 'utf-8'))
    except re.error as ex:
        sys.stderr.write('Wrong regexp {0}: {1} \n'.format(args.PATTERNS, ex))
        sys.exit(1)

    if args.infile is not None and os.path.isfile(args.infile):
        fd = open(args.infile, 'rb')
    else:
        fd = sys.stdin.buffer

    while True:
        buf = fd.read(4)
        if buf == b'WPA*':
            buf = buf + fd.readline()
            target = parse_combined(buf)
        elif buf == b'HCPX':
            buf = buf + fd.read(393 - 4)
            target = parse_hccapx(buf)
        else:
            buf = buf + fd.readline()
            target = parse_pmkid(buf)

        if not buf:
            break

        if target is None:
            sys.stderr.write('Unrecognized input format\n')
            sys.exit(1)

        res = regexp.search(target)
        if (res is not None and not args.v) or (res is None and args.v):
            sys.stdout.buffer.write(buf)
