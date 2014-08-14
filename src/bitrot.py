#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
# Copyright (C) 2013 by Łukasz Langa

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# ------------------------------------------------------------------------------
# check files against bitrot
# bitrot errors are here defined as a file having a SHA1 hash being different
# from the last time we checked, while not being modified (through the meta-
# data attribute mtime).
# the tool exits with error codes:
#   0 - no bitrot detected
#   1 - bitrot(-s) detected
#   2 - database error (does not exist)
# ------------------------------------------------------------------------------
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
# ------------------------------------------------------------------------------
import argparse
import atexit
import datetime
import errno
import functools
import hashlib
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
import logging
# ------------------------------------------------------------------------------
DEFAULT_CHUNK_SIZE = 16384
DOT_THRESHOLD = 200
VERSION = (0, 6, 0)
LOG_FILENAME = '.bitrot.log'
DATABASE_FILENAME = b'.bitrot.db'
# ------------------------------------------------------------------------------
def get_logger(verbosity = 1):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # write logs to file
    filehandler = logging.FileHandler(LOG_FILENAME)
    filehandler.setLevel(logging.INFO)
    filehandler.setFormatter(formatter)
    logger.addHandler(filehandler)

    if verbosity > 0:
        # write logs also to stdout, ie if not running as 'quiet'
        stdouthandler = logging.StreamHandler(sys.stdout)
        stdouthandler.setLevel(logging.INFO)
        stdouthandler.setFormatter(formatter)
        logger.addHandler(stdouthandler)

    return logger
# ------------------------------------------------------------------------------
# get the SHA1 hash of a file
def sha1(path, chunk_size):
    digest = hashlib.sha1()
    with open(path, 'r') as f:
        d = f.read(chunk_size)
        while d:
            digest.update(d)
            d = f.read(chunk_size)
    return digest.hexdigest()
# ------------------------------------------------------------------------------
def throttled_commit(conn, commit_interval, last_commit_time):
    if time.time() - last_commit_time > commit_interval:
        conn.commit()
        last_commit_time = time.time()
    return last_commit_time
# ------------------------------------------------------------------------------
def get_sqlite3_cursor(path, copy=False):
    if copy:
        if not os.path.exists(path):
            raise ValueError("error: bitrot database at {} does not exist."
                             "".format(path))
        db_copy = tempfile.NamedTemporaryFile(prefix='bitrot_', suffix='.db',
                                              delete=False)
        with open(path, 'rb') as db_orig:
            try:
                shutil.copyfileobj(db_orig, db_copy)
            finally:
                db_copy.close()
        path = db_copy.name
        atexit.register(os.unlink, path)
    conn = sqlite3.connect(path)
    atexit.register(conn.close)
    cur = conn.cursor()
    tables = set(t for t, in cur.execute('SELECT name FROM sqlite_master'))
    if 'bitrot' not in tables:
        cur.execute('CREATE TABLE bitrot (path TEXT PRIMARY KEY, '
                    'mtime INTEGER, hash TEXT, timestamp TEXT)')
    if 'bitrot_hash_idx' not in tables:
        cur.execute('CREATE INDEX bitrot_hash_idx ON bitrot (hash)')
    atexit.register(conn.commit)
    return conn
# ------------------------------------------------------------------------------
def run(verbosity=1, check=False, follow_links=False, commit_interval=300,
        chunk_size=DEFAULT_CHUNK_SIZE, list_dbase = False):
    lgr = get_logger(verbosity)
    lgr.info('**** Starting tool ****')
    current_dir = b'.'   # sic, relative path

    # get and open the database
    bitrot_db = os.path.join(current_dir, DATABASE_FILENAME)
    try:
        conn = get_sqlite3_cursor(bitrot_db, copy=check)
    except ValueError:
        lgr.info('No database exists so cannot check. Run the tool once first.')
        sys.exit(2)
    cur = conn.cursor()

    # init variables
    error_paths = []
    new_paths = []
    updated_paths = []
    renamed_paths = []
    paths = []
    error_count = 0
    total_size = 0
    current_size = 0
    last_reported_size = ''
    missing_paths = set()
    cur.execute('SELECT path FROM bitrot')

    # get the paths stored in the database
    row = cur.fetchone()
    while row:
        missing_paths.add(row[0])
        row = cur.fetchone()
    for path, _, files in os.walk(current_dir):
        for f in files:
            p = os.path.join(path, f)
            p_uni = p.decode('utf8')
            try:
                if follow_links or p_uni in missing_paths:
                    st = os.stat(p)
                else:
                    st = os.lstat(p)
            except OSError as ex:
                if ex.errno != errno.ENOENT:
                    raise
            else:
                if not stat.S_ISREG(st.st_mode) or p == bitrot_db:
                    continue
                paths.append(p)
                total_size += st.st_size
    paths.sort()
    last_commit_time = 0
    tcommit = functools.partial(throttled_commit, conn, commit_interval)
    if list_dbase:
        print('Files in database:')
        for p in paths:
            print('  ' + str(p))
        sys.exit(0)

    # go through the files and check
    for p in paths:
        st = os.stat(p)
        new_mtime = int(st.st_mtime)
        current_size += st.st_size

        # progress report
        if verbosity:
            size_fmt = '\rProgress: {:>6.1%}'.format(current_size/(total_size or 1))
            if size_fmt != last_reported_size:
                sys.stdout.write(size_fmt)
                sys.stdout.flush()
                last_reported_size = size_fmt
        p_uni = p.decode('utf8')
        missing_paths.discard(p_uni)
        try:
            new_sha1 = sha1(p, chunk_size)
        except (IOError, OSError) as e:
            if verbosity:
                lgr.info(
                    '\rwarning: cannot compute hash of {} [{}]'.format(
                        p, errno.errorcode[e.args[0]],
                    ),
                    file=sys.stderr,
                )
            continue
        update_ts = datetime.datetime.utcnow().strftime(
            '%Y-%m-%d %H:%M:%S%z'
        )
        cur.execute('SELECT mtime, hash, timestamp FROM bitrot WHERE path=?', (p_uni,))
        row = cur.fetchone()
        if not row:
            cur.execute('SELECT mtime, path, timestamp FROM bitrot WHERE '
                        'hash=?', (new_sha1,))
            rows = cur.fetchall()
            for row in rows:
                stored_mtime, stored_path, update_ts = row
                if not os.path.exists(stored_path):
                    renamed_paths.append((stored_path, p_uni))
                    missing_paths.discard(stored_path)
                    cur.execute('UPDATE bitrot SET mtime=?, path=?, '
                                'timestamp=? WHERE hash=?',
                                (new_mtime, p_uni, update_ts, new_sha1))

                    last_commit_time = tcommit(last_commit_time)
                    break
            else:
                new_paths.append(p)
                cur.execute(
                    'INSERT INTO bitrot VALUES (?, ?, ?, ?)',
                    (p_uni, new_mtime, new_sha1, update_ts),
                )
                last_commit_time = tcommit(last_commit_time)
            continue
        stored_mtime, stored_sha1, update_ts = row
        if int(stored_mtime) != new_mtime:
            updated_paths.append(p)
            cur.execute('UPDATE bitrot SET mtime=?, hash=?, timestamp=? '
                        'WHERE path=?',
                        (new_mtime, new_sha1, update_ts, p_uni))
            last_commit_time = tcommit(last_commit_time)
        elif stored_sha1 != new_sha1:
            error_paths.append(p)
            error_count += 1

    if verbosity:
        # we need a newline for more clean output
        sys.stdout.write('\n')
        sys.stdout.flush()
        lgr.info('all files checked')
        if len(error_paths) > 0:
            lgr.info('**** errors detected ****')

    for path in missing_paths:
        cur.execute('DELETE FROM bitrot WHERE path=?', (path,))
        last_commit_time = tcommit(last_commit_time)
    conn.commit()
    cur.execute('SELECT COUNT(path) FROM bitrot')
    all_count = cur.fetchone()[0]

    # report
    if verbosity:
        lgr.info('Finished. {:.2f} MiB of data read. {} errors found.'
              ''.format(total_size/1024/1024, error_count))
        lgr.info(
            '{} entries in the database, {} errors, {} new, {} updated, '
            '{} renamed, {} missing.'.format(
                all_count, len(error_paths), len(new_paths), len(updated_paths),
                len(renamed_paths), len(missing_paths),
            ),
        )
        if error_paths:
            lgr.info('{} entries with errors:'.format(len(error_paths)))
            error_paths.sort()
            for path in error_paths:
                lgr.info('  ' + path)
        if new_paths:
            lgr.info('{} entries new:'.format(len(new_paths)))
            new_paths.sort()
            for path in new_paths:
                lgr.info('  ' + path)
        if updated_paths:
            lgr.info('{} entries has changed:'.format(len(updated_paths)))
            updated_paths.sort()
            for path in updated_paths:
                lgr.info('  ' + path)
        if renamed_paths:
            lgr.info('{} entries renamed:'.format(len(renamed_paths)))
            renamed_paths.sort()
            for path in renamed_paths:
                lgr.info('  from', path[0], 'to', path[1])
        if missing_paths:
            lgr.info('{} entries missing:'.format(len(missing_paths)))
            missing_paths = sorted(missing_paths)
            for path in missing_paths:
                lgr.info('  ' + path)
        if not any((new_paths, updated_paths, missing_paths)):
            lgr.info()
        if check:
            lgr.info('warning: database file not updated on disk (check mode).')

    # if there are bitrot detected, we exit with error code
    if error_count:
        sys.exit(1)
    else:
        sys.exit(0)
# ------------------------------------------------------------------------------
def stable_sum():
    current_dir = b'.'   # sic, relative path
    bitrot_db = os.path.join(current_dir, DATABASE_FILENAME)
    digest = hashlib.sha512()
    conn = get_sqlite3_cursor(bitrot_db)
    cur = conn.cursor()
    cur.execute('SELECT hash FROM bitrot ORDER BY path')
    row = cur.fetchone()
    while row:
        digest.update(row[0])
        row = cur.fetchone()
    return digest.hexdigest()
# ------------------------------------------------------------------------------
def run_from_command_line():
    parser = argparse.ArgumentParser(prog='bitrot')
    parser.add_argument(
        '-f', '--follow-links', action='store_true',
        help='follow symbolic links and store target files\' hashes. Once '
             'a path is present in the database, it will be checked against '
             'changes in content even if it becomes a symbolic link. In '
             'other words, if you run `bitrot -l`, on subsequent runs '
             'symbolic links registered during the first run will be '
             'properly followed and checked even if you run without `-l`.')
    parser.add_argument(
        '-q', '--quiet', action='store_true',
        help='don\'t print anything besides checksum errors')
    parser.add_argument(
        '-s', '--sum', action='store_true',
        help='using only the data already gathered, return a SHA-512 sum '
             'of hashes of all the entries in the database. No timestamps '
             'are used in calculation.')
    parser.add_argument(
        '-c', '--check', action='store_true',
        help='check files against the existing database. This will not update the database.')
    parser.add_argument(
        '-l', '--list', action='store_true',
        help='List the contents of the database, ie what files we checked last.')
    parser.add_argument(
        '--version', action='version',
        version='%(prog)s {}.{}.{}'.format(*VERSION))
    parser.add_argument(
        '--commit-interval', type=float, default=300,
        help='min time in seconds between commits '
             '(0 commits on every operation)')
    parser.add_argument(
        '--chunk-size', type=int, default=DEFAULT_CHUNK_SIZE,
        help='read files this many bytes at a time')
    args = parser.parse_args()
    if args.sum:
        try:
            print(stable_sum())
        except RuntimeError as e:
            print(unicode(e).encode('utf8'))
    else:
        verbosity = 1
        if args.quiet:
            verbosity = 0
        run(
            verbosity=verbosity,
            check=args.check,
            follow_links=args.follow_links,
            commit_interval=args.commit_interval,
            chunk_size=args.chunk_size,
            list_dbase = args.list
        )
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    run_from_command_line()
# ------------------------------------------------------------------------------