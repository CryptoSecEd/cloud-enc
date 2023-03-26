"""Encrypt files and upload to the cloud

Todo: Add counts
Scan through all files in encrypted backup folder, delete any that
 1. Do not have a corresponding plaintext file and
 2. The ciphertext file is more than EXPIRATION days old
Count files that have been newly encrypted and files that have been 
updated separately.
Fail gracefully if wrong decryption private key provided.
Add an argument to specify a different public key
"""

import sys

from argparse import ArgumentParser
from Cryptodome.Cipher import AES
from datetime import datetime
from ecies import encrypt, decrypt
from os import mkdir
from pathlib import Path
from secrets import token_bytes
from time import time


AES_KEY_SIZE = 32       # 32 bytes = 256 bit key
CIPHERBLOCK = 16
# EXPIRATION = 10.0/(24*60*60)
EXPIRATION = 30         # In days
EXPIRATION_SEC = EXPIRATION*24*60*60

def change_path(src, dst, rest):
    """ Generate a new Path where src is replaced by dst
    """
    out_parts = dst.parts + rest.parts[len(src.parts):]
    out = Path(out_parts[0])
    out_parts = out_parts[1:]

    while (len(out_parts)>0):
        out = Path(out, Path(out_parts[0]))
        out_parts = out_parts[1:]
    
    return(out)


def enc_file(pubkey, plainfile, cipherfile):
    """Use the public key to encrypt the file. The ciphertext filename
    is just the plaintext filename with an added ".enc" extension.
    The file contains:
    'cenc1'+<len enc key>+<public key encrypted random key>
    +<encrypted file>+<MAC>
    The '1' after 'boca' is the version number
    Some links I've used for reference:
    https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html
    https://pypi.org/project/eciespy/
    https://nitratine.net/blog/post/python-gcm-encryption-tutorial/
        #encryption-planning

    :param pubkey: The public key used to encrypt the file.
    :type pubkey: ``str``
    :param plainfile: The name of the plaintext file.
    :type filename: ``pathlib.Path``
    :param cipherfile: The name of the ciphertext file.
    :type filename: ``pathlib.Path``
    :returns: The ciphertext filename.
    :rtype: ``pathlib.Path``
    """

    cloud_enc_version = 1
    header = b'cenc'+bytes([cloud_enc_version])

    aes_key = token_bytes(AES_KEY_SIZE)
    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    aes_cipher.update(header)
    encrypted_key = encrypt(pubkey, aes_key+aes_cipher.nonce)

    cipherfile = Path(str(cipherfile)+".enc")

    if not cipherfile.parents[0].is_dir():
        Path(cipherfile.parents[0]).mkdir(parents=True, exist_ok=True)
        # print(f"Created folder: {cipherfile.parents[0]}")

    retval = ""

    if cipherfile.is_file():
        # print(f"File already exists: {cipherfile}")
        plain_time = plainfile.stat().st_mtime
        cipher_time = cipherfile.stat().st_mtime
        if (plain_time > cipher_time):
            # print(f"File {plainfile} has updated. Deleting encrypted file")
            cipherfile.unlink()
            retval = "Updated"
        else:
            # print(f"File {plainfile} has not updated. Not encrypting.")
            return "Exists"

    with open(cipherfile, 'xb') as file_out:
        file_out.write(header)
        file_out.write((len(encrypted_key)).to_bytes(2, byteorder='big'))
        file_out.write(encrypted_key)

        with open(plainfile, 'rb') as file_in:
            plain_block = file_in.read(CIPHERBLOCK)
            while plain_block != b'':
                cipher_block = aes_cipher.encrypt(plain_block)
                file_out.write(cipher_block)
                plain_block = file_in.read(CIPHERBLOCK)
            tag = aes_cipher.digest()
            file_out.write(tag)

    pending_file = Path(str(cipherfile)[:-1]+"x")
    
    # if the pending file exists, delete it
    # Todo: Integrate this with the counts
    if pending_file.is_file():
        pending_file.unlink()

    if retval == "Updated":
        return retval
    else:
        return "New"


def main():
    parser = ArgumentParser(description="Encrypt files and upload to the " +
                            "cloud")
    parser.add_argument("--source", help="Location of files to backup.",
                        type=str)
    parser.add_argument("--dest", help="Location to save encrypted files",
                        type=str)

    pub_key = b'\x03R6$>\xec\x03\xd3\xc2!\xd8\xe1\xe6\xebp6\xcfM#P\x10N\x16\x143\xd5\xf7\xe8\xb3N\xae%z'

    args = parser.parse_args()
    if not args.source:
        print("Please enter the location of the files to be backed up with" +
              " the --source argument")
        sys.exit(1)
    if not args.dest:
        print("Please enter the location where the encrypted files are to be" +
              " stored the --dest argument")
        sys.exit(1)
    
    print(f"Starting encrypting/backing up at {datetime.now()}")

    source = Path(args.source)
    dest = Path(args.dest)

    if not source.is_dir():
        print(f"Source input {source} is not a directory.")
        sys.exit(1)
        
    if dest.is_file():
        print(f"Destination input {dest} is a file. Please provide a folder")
        sys.exit(1)
    elif not dest.is_dir():
        Path(dest).mkdir(parents=True, exist_ok=True)
        print(f"Created folder: {dest}")

    print(f"Source location: {source}")
    print(f"Destination location: {dest}")

    if not source.is_absolute():
        source = source.resolve()

    if not dest.is_absolute():
        dest = dest.resolve()

    new_count = 0
    exists_count = 0
    updated_count = 0
    for file in source.rglob("*"):
        if not file.is_dir():
            enc_path = change_path(source, dest, file)
            retval = enc_file(pub_key, file, enc_path)
            if retval == "New":
                new_count += 1
            elif retval == "Exists":
                exists_count += 1
            elif retval == "Updated":
                updated_count += 1

    print(f"Number of newly encrypted files: {new_count}")
    print(f"Number of unchanged files (not encrypted): {exists_count}")
    print(f"Number of updated files re-encrypted: {updated_count}")
    
    delete_count = 0
    for cipher_file in dest.rglob("*"):
        if not cipher_file.is_dir():
            original_file = change_path(dest, source, cipher_file)
            original_file = Path(str(original_file)[:-4])

            cipher_enc = Path(cipher_file.parent, f"{cipher_file.stem}.enc")
            cipher_enx = Path(cipher_file.parent, f"{cipher_file.stem}.enx")

            # All encrypted files should have either .enc or .enx
            # extensions
            if cipher_file.suffix not in (".enc", ".enx"):
                print("Invalid extension for file in destination: " +
                      {cipher_file})
                exit(1)
            # If the .enc file exists and the original does not, rename
            # the .enc to enx and touch
            if not original_file.is_file() and cipher_enc.is_file():
                cipher_file.rename(cipher_enx)
                cipher_enx.touch()

            # If both .enc and .enx files exist, we keep the most recent
            # file
            elif cipher_enc.is_file() and cipher_enx.is_file():
                if cipher_enx.stat().st_mtime > cipher_enc.stat().st_mtime:
                    cipher_enc.unlink()
                else:
                    cipher_enx.unlink()
                    cipher_enc.rename(cipher_enx)
                    cipher_enx.touch()

            # If the .enx file exists and the .enc file does not and
            # the file is past expiration, then delete
            elif cipher_enx.is_file() and not cipher_enc.is_file():
                if cipher_file.stat().st_mtime - (time() - EXPIRATION_SEC):
                    cipher_file.unlink()
                    delete_count += 1

    print(f"Number of deleted files: {delete_count}")

    print(f"Finished encrypting/backing up at {datetime.now()}")


if __name__ == "__main__":
    main()