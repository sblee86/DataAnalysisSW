#!/usr/bin/env python3
"""Regenerate the embedded binary account resource; rebuild to apply changes."""
import getpass, hashlib, secrets, struct, os, subprocess
from pathlib import Path

def encode_string(value):
    raw=value.encode('utf-8'); count=len(raw); prefix=bytearray()
    while count>=128:
        prefix.append((count & 127)|128); count >>= 7
    prefix.append(count)
    return bytes(prefix)+raw

def main():
    data=encode_string('LANSCOPE-AUTH-1')+struct.pack('<i',2)
    passwords={}
    for user,role in [('admin',1),('guest',0)]:
        password=getpass.getpass(f'{user} new password (min. 10 chars): ')
        if len(password)<10: raise SystemExit('Password must be at least 10 characters')
        if password!=getpass.getpass('Confirm password: '): raise SystemExit('Passwords do not match')
        passwords[user]=password
        salt=secrets.token_bytes(16)
        data+=encode_string(user)+bytes([role])+struct.pack('<i',600000)+salt+hashlib.pbkdf2_hmac('sha256',password.encode(),salt,600000,32)
    path=Path(__file__).resolve().parents[1]/'src/LanScope/Resources/accounts.bin'
    root=path.parents[3]
    tracked=[path,path.parent/'policy-public.bin',path.parent/'samples.bin']
    before={p:p.read_bytes() if p.exists() else None for p in tracked}
    try:
        path.write_bytes(data)
        process_env=os.environ.copy()
        process_env.update(LANSCOPE_TEST_ADMIN=passwords['admin'],LANSCOPE_TEST_GUEST=passwords['guest'])
        subprocess.run(['dotnet','run','--project','tests/LanScope.Checks','--',str(root),'--prepare-resources'],cwd=root,env=process_env,check=True)
    except BaseException:
        for p,content in before.items():
            if content is None: p.unlink(missing_ok=True)
            else: p.write_bytes(content)
        raise
    print('Updated account hashes, policy public key and encrypted demo resources. Rebuild to apply.')
    print('Existing deployed ICD vaults use the OLD admin key. Migrate/export with the old build before replacing it.')
if __name__=='__main__': main()
