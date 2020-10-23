#!/usr/bin/python

"""
    SPDX-License-Identifier: GPL-3.0-or-later
    Verify the hashes from the AACS content certificate(s).

    Copyright (C) 2020 Michael Mohr

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
    This tool verifies that the truncated hash values stored in the content
    hash table (assisted by information from the content certificate) match
    the calculated hash values for each hash unit on a Blu-Ray disc.

    Support is present for both UHD (4K) as well as HD Blu-Ray discs.

    The hashes are calculated against the disc content *after* bus encryption
    has been removed (if present), but *before* AACS decryption.
"""

import os
import sys
import struct
import collections
from cStringIO import StringIO
import hashlib
import multiprocessing


HASH_UNIT_SIZE = 96 * 2048


ContentHashDescriptor = collections.namedtuple(
    'ContentHashDescriptor', 'hash_values stream_path hu_offset'
)


class ContentError(Exception):
    pass


def get_checksums(mount_point):
    cht_checksums = []
    digests = []
    hash_values = []
    cert_types = set()
    hu_counts = set()
    layer_counts = set()
    layer_num = None
    for layer_num in range(4):
        ccp = os.path.join(
            mount_point, 'AACS', 'Content{0:03d}.cer'.format(layer_num)
        )
        chp = os.path.join(
            mount_point, 'AACS', 'ContentHash{0:03d}.tbl'.format(layer_num)
        )
        if not (os.path.exists(ccp) and os.path.exists(chp)):
            break
        layer_cert = parse_content_certificate(ccp)
        cert_types.add(layer_cert['Certificate Type'])
        hu_counts.add(layer_cert['Total Number of HashUnits'])
        layer_counts.add(layer_cert['Total Number of Layers'])
        layer_digests, layer_hvs = parse_content_hash(
            file_path=chp,
            digest_count=layer_cert['Number of Digests'],
            hash_unit_count=layer_cert['Number of HashUnits'],
        )
        cht_checksums += layer_cert['Content Hash Table Digests']
        digests += layer_digests
        hash_values += layer_hvs
    if len(cert_types) != 1:
        raise ContentError('No consensus on certificate type')
    cert_type = cert_types.pop()
    if cert_type == 16:
        is_uhd = True
    elif cert_type == 0:
        is_uhd = False
    else:
        raise ContentError('Unsupported certificate type')
    if len(hu_counts) != 1:
        raise ContentError('No consensus on hash unit counts')
    if hu_counts.pop() != len(hash_values):
        raise ContentError(
            'Mismatched reported vs actual hash unit counts'
        )
    if len(layer_counts) != 1:
        raise ContentError('No consensus on layer counts')
    if layer_counts.pop() != layer_num:
        raise ContentError(
            'Reported layer count disagrees with observed file presence'
        )
    results = []
    for dgst_idx in range(len(digests)):
        min_hv_idx = digests[dgst_idx].starting_hu
        try:
            max_hv_idx = digests[dgst_idx+1].starting_hu
        except IndexError:
            max_hv_idx = len(hash_values)
        digest_hvs = hash_values[min_hv_idx:max_hv_idx]
        if is_uhd:
            m = hashlib.sha256()
        else:
            m = hashlib.sha1()
        for digest_hv in digest_hvs:
            m.update(digest_hv)
        cht_checksum = m.digest()[-8:]
        if cht_checksum != cht_checksums[dgst_idx]:
            raise ContentError(
                'Content Hash Table checksum comparison failed'
            )
        results.append(
            ContentHashDescriptor(
                hash_values=digest_hvs,
                stream_path=digests[dgst_idx].stream_path,
                hu_offset=digests[dgst_idx].hu_offset
            )
        )
    return results, is_uhd


class HashUnitProcessor(object):

    def __init__(self, stream_fn, hu_offset, is_uhd):
        self._stream_fn = stream_fn
        self._hu_offset = hu_offset
        self._is_uhd = is_uhd

    def __call__(self, hash_index):
        file_offset = (self._hu_offset + hash_index) * HASH_UNIT_SIZE
        with open(self._stream_fn, 'r') as stream_fd:
            stream_fd.seek(file_offset, os.SEEK_SET)
            hu_data = stream_fd.read(HASH_UNIT_SIZE)
        if len(hu_data) != HASH_UNIT_SIZE:
            raise ContentError("Unable to read all hash unit data")
        if self._is_uhd:
            m = hashlib.sha256()
        else:
            m = hashlib.sha1()
        m.update(hu_data)
        return m.digest()[-8:]


def verify_checksums(mount_point):
    # Increase the process count if verifying from flash-backed storage
    pool = multiprocessing.Pool(processes=1)
    chds, is_uhd = get_checksums(mount_point)
    try:
        for chd in chds:
            sys.stdout.write(
                'Verifying ' + chd.stream_path[-1] + '... '
            )
            sys.stdout.flush()
            p = HashUnitProcessor(
                stream_fn=os.path.join(
                    mount_point, *chd.stream_path
                ),
                hu_offset=chd.hu_offset,
                is_uhd=is_uhd,
            )
            hash_values = pool.map(p, range(len(chd.hash_values)))
            if hash_values == chd.hash_values:
                print 'PASS'
            else:
                print 'FAIL'
        pool.close()
    except KeyboardInterrupt:
        pool.terminate()
    pool.join()


def parse_content_certificate(file_path):
    with open(file_path) as _cc_fd:
        _cc_data = _cc_fd.read()
    if len(_cc_data) != os.path.getsize(file_path):
        raise ContentError('Unable to read content certificate')
    cc_data = StringIO(_cc_data)
    fields = struct.unpack('>BBIBBIHHIHHH', cc_data.read(26))
    format_specific_section = cc_data.read(fields[11])
    cert_fields = {
        'Certificate Type': fields[0],
        'Bus Encryption Enabled': (fields[1] >> 7) == 1,
        'Reserved Area 1': fields[1] & 0x7F,
        'Total Number of HashUnits': fields[2],
        'Total Number of Layers': fields[3],
        'Layer Number': fields[4],
        'Number of HashUnits': fields[5],
        'Number of Digests': fields[6],
        'Applicant ID': fields[7],
        'Bit field 1': fields[8],
        'Minimum CRL Version': fields[9],
        'Reserved Area 2': fields[10],
        'Format Specific Section': format_specific_section,
    }
    cht_digests = []
    for _ in range(fields[6]):
        cht_digests.append(cc_data.read(8))
    cert_fields['Content Hash Table Digests'] = cht_digests
    # Remaining content is signature data
    return cert_fields


def parse_content_hash(file_path, digest_count, hash_unit_count):
    if os.path.getsize(file_path) != (12*digest_count+8*hash_unit_count):
        raise ContentError('Unable to parse content hash table')
    with open(file_path) as ch_fd:
        _ch_data = ch_fd.read()
    if len(_ch_data) != os.path.getsize(file_path):
        raise ContentError('Unable to read content hashes')
    ch_data = StringIO(_ch_data)
    Digest = collections.namedtuple(
        'Digest', 'starting_hu stream_path hu_offset'
    )
    digests = []
    for _ in range(digest_count):
        dgst = struct.unpack('>III', ch_data.read(12))
        digests.append(
            Digest(
                starting_hu=dgst[0],
                stream_path=(
                    'BDMV', 'STREAM', '{0:05d}.m2ts'.format(dgst[1])
                ),
                hu_offset=dgst[2],
            )
        )
    hash_values = []
    for _ in range(hash_unit_count):
        hash_values.append(ch_data.read(8))
    assert ch_data.tell() == os.path.getsize(file_path)
    return digests, hash_values


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'error - must provide mount point'
        sys.exit(1)
    try:
        verify_checksums(sys.argv[1])
        sys.exit(0)
    except ContentError as _ce:
        print 'ERROR: ' + str(_ce)
        sys.exit(1)
