#!/usr/bin/env python3
"""Regenerate the embedded binary account resource; rebuild to apply changes."""
import getpass, hashlib, secrets, struct
from pathlib import Path

def encode_string(value):
    raw=value.encode('utf-8'); count=len(raw); prefix=bytearray()
    while count>=128:
        prefix.append((count & 127)|128); count >>= 7
    prefix.append(count)
    return bytes(prefix)+raw

def main():
    data=encode_string('LANSCOPE-AUTH-1')+struct.pack('<i',2)
    for user,role in [('admin',1),('guest',0)]:
        password=getpass.getpass(f'{user} new password (min. 10 chars): ')
        if len(password)<10: raise SystemExit('Password must be at least 10 characters')
        if password!=getpass.getpass('Confirm password: '): raise SystemExit('Passwords do not match')
        salt=secrets.token_bytes(16)
        data+=encode_string(user)+bytes([role])+struct.pack('<i',600000)+salt+hashlib.pbkdf2_hmac('sha256',password.encode(),salt,600000,32)
    path=Path(__file__).resolve().parents[1]/'src/LanScope/Resources/accounts.bin'
    path.write_bytes(data)
    print('Updated accounts.bin (salted PBKDF2 hashes only). Rebuild the app to apply.')
if __name__=='__main__': main()
