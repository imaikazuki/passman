#!/usr/bin/env python

# Copyright (c) 2016 IMAI Kazuki
# Released under the MIT license
# http://opensource.org/licenses/mit-license.php

import getpass
import json
import os
import sys
import xerox

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

dbfile = '.passmandb'
dbpath = os.environ['HOME'] + '/' + dbfile

def load(password):
    backend = default_backend()
    f = open(dbpath, 'br')
    salt = f.read(16)
    nonce = f.read(16)
    key = key_stretching(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
    decryptor = cipher.decryptor()
    pt = decryptor.update(f.read()) + decryptor.finalize()
    db = json.loads(pt.decode('utf-8'))
    f.close()
    return db

def save(db, password):
    backend = default_backend()
    salt = os.urandom(16)
    key = key_stretching(password, salt)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(bytes(json.dumps(db), 'utf-8')) + encryptor.finalize()

    f = open(dbpath, 'bw')
    f.write(salt)
    f.write(nonce)
    f.write(ct)
    f.close()

def key_stretching(password, salt):
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
        )
    key = kdf.derive(bytes(password, 'utf-8'))
    return key

args = sys.argv

command = args[1]
if 'init' == command:
    try:
        open(dbpath, 'br').close()
    except FileNotFoundError as error:
        pass
    else:
        sys.stderr.write('Database is already exist.\n')
        sys.exit(-1)
    password0 = getpass.getpass('Master password: ')
    password1 = getpass.getpass('Re-type master password: ')
    if password0 != password1:
        sys.stderr('Password not matched\n')
        sys.exit(-1)
    db = json.loads('{}')
    save(db, password0)

elif 'add' == command:
    service = args[2]
    password = getpass.getpass('Master password: ')
    db = load(password)
    if service in db.keys():
        sys.stderr.write('Service already exist.\n')
        sys.exit(-1)
    db[service] = {}
    save(db, password)

elif 'list' == command:
    password = getpass.getpass('Master password: ')
    db = load(password)
    for service in db.keys():
        sys.stdout.write(service + '\n')

elif 'purge' == command:
    service = args[2]
    password = getpass.getpass('Master password: ')
    db = load(password)
    if service in db.keys():
        del db[service]
        sys.stdout.write('Service deleted.\n')
    else:
        sys.stderr.write('No such service.\n')
        sys.exit(-1)
    save(db, password)

elif 'get' == command:
    service = args[2]
    key = args[3]
    password = getpass.getpass('Master password: ')
    db = load(password)
    if service in db.keys():
        if key in db[service].keys():
            sys.stdout.write(db[service][key] + '\n')
        else:
            sys.stderr.write('No such key for the service.\n')
            sys.exit(-1)
    else:
        sys.stderr.write('No such service.\n')
        sys.exit(-1)

elif 'clip' == command:
    service = args[2]
    key = args[3]
    password = getpass.getpass('Master password: ')
    db = load(password)
    if service in db.keys():
        if key in db[service].keys():
            xerox.copy(db[service][key])
        else:
            sys.stderr.write('No such key for the service.\n')
            sys.exit(-1)
    else:
        sys.stderr.write('No such service.\n')
        sys.exit(-1)

elif 'set' == command:
    service = args[2]
    key = args[3]
    value = args[4]
    password = getpass.getpass('Master password: ')
    db = load(password)
    if service in db.keys():
        db[service][key] = value
        save(db, password)
    else:
        sys.stderr.write('No such service.\n')

elif 'keys' == command:
    service = args[2]
    password = getpass.getpass('Master password: ')
    db = load(password)
    if service in db.keys():
        for key in db[service].keys():
            sys.stdout.write(key + '\n')
    else:
        sys.stderr.write('No such service.\n')

elif 'remove' == command:
    service = args[2]
    key = args[3]
    password = getpass.getpass('Master password: ')
    db = load(password)
    if service in db.keys():
        if key in db[service].keys():
            del db[service][key]
            save(db, password)
            sys.stdout.write('Key deleted.\n')
        else:
            sys.stderr.write('No such key for the sercie.\n')
    else:
        sys.stderr.write('No such service.\n')

elif 'change' == command:
    oldpass = getpass.getpass('Old master password: ')
    newpass = getpass.getpass('New master password: ')
    save(load(oldpass), newpass)
