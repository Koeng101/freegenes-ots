import sys

import argparse
import binascii
import io
import logging
import os
import time
import urllib.request
import threading
import bitcoin
import bitcoin.rpc
from queue import Queue, Empty

from bitcoin.core import b2x, b2lx, lx, CTxOut, CTransaction
from bitcoin.core.script import CScript, OP_RETURN

from binascii import hexlify

from opentimestamps.core.notary import *
from opentimestamps.core.timestamp import *
from opentimestamps.core.op import *
from opentimestamps.core.serialize import *
from opentimestamps.timestamp import *
from opentimestamps.bitcoin import *

import opentimestamps.calendar

import otsclient
import io

def remote_calendar(calendar_uri):
    """Create a remote calendar with User-Agent set appropriately"""
    return opentimestamps.calendar.RemoteCalendar(calendar_uri,
                                                  user_agent="OpenTimestamps-Client/%s" % otsclient.__version__)

def submit_async(calendar_url, msg, q, timeout):

    def submit_async_thread(remote, msg, q, timeout):
        try:
            calendar_timestamp = remote.submit(msg, timeout=timeout)
            q.put(calendar_timestamp)
        except Exception as exc:
            q.put(exc)

    logging.info('Submitting to remote calendar %s' % calendar_url)
    remote = remote_calendar(calendar_url)
    t = threading.Thread(target=submit_async_thread, args=(remote, msg, q, timeout))
    t.start()


def create_timestamp(timestamp, calendar_urls, timeout):
    """Create a timestamp

    calendar_urls - List of calendar's to use
    setup_bitcoin - False if Bitcoin timestamp not desired; set to
                    args.setup_bitcoin() otherwise.
    """
    n = len(calendar_urls)

    q = Queue()
    for calendar_url in calendar_urls:
        submit_async(calendar_url, timestamp.msg, q, timeout)

    start = time.time()
    merged = 0
    for i in range(n):
        try:
            remaining = max(0, timeout - (time.time() - start))
            result = q.get(block=True, timeout=remaining)
            try:
                if isinstance(result, Timestamp):
                    timestamp.merge(result)
                    merged += 1
                else:
                    logging.debug(str(result))
            except Exception as error:
                logging.debug(str(error))

        except Empty:
            # Timeout
            continue


calendar_urls = ['https://a.pool.opentimestamps.org','https://b.pool.opentimestamps.org','https://a.pool.eternitywall.com','https://ots.btc.catallaxy.com']

def TimeStamp(data, calendar_urls=calendar_urls):
    fake_file = io.BytesIO()
    file_timestamp= DetachedTimestampFile.from_fd(OpSHA256(), data)
    file_timestamps = []
    merkle_roots = []

    nonce_appended_stamp = file_timestamp.timestamp.ops.add(OpAppend(os.urandom(16)))
    merkle_root = nonce_appended_stamp.ops.add(OpSHA256())

    merkle_roots.append(merkle_root)
    file_timestamps.append(file_timestamp)
    merkle_tip = make_merkle_tree(merkle_roots)
    create_timestamp(merkle_tip, calendar_urls, 10)
    
    HEADER_MAGIC = b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94'
    """Header magic bytes

    Designed to be give the user some information in a hexdump, while being
    identified as 'data' by the file utility.
    """
    MIN_FILE_DIGEST_LENGTH = 20 # 160-bit hash
    MAX_FILE_DIGEST_LENGTH = 32 # 256-bit hash

    MAJOR_VERSION = 1

    ctx = StreamSerializationContext(fake_file)
    file_timestamp.serialize(ctx)

    fake_file.write(HEADER_MAGIC)
    value = 1
    if value == 0:
        fake_file.write(b'\x00')

    else:
        while value != 0:
            b = value & 0b01111111
            if value > 0b01111111:
                b |= 0b10000000
            fake_file.write(bytes([b]))
            if value <= 0b01111111:
                break
            value >>= 7
    file_timestamp.file_hash_op.serialize(ctx)
    assert file_timestamp.file_hash_op.DIGEST_LENGTH == len(file_timestamp.timestamp.msg)
    ctx.write_bytes(file_timestamp.timestamp.msg)

    file_timestamp.file_hash_op.serialize(ctx)
    assert file_timestamp.file_hash_op.DIGEST_LENGTH == len(file_timestamp.timestamp.msg)
    ctx.write_bytes(file_timestamp.timestamp.msg)
    file_timestamp.timestamp.serialize(ctx)
    return fake_file.getvalue()
