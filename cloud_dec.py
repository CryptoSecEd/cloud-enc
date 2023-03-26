"""Download files from cloud and decrypt
"""

import sys

from argparse import ArgumentParser
from datetime import datetime
from Cryptodome.Cipher import AES
from ecies import encrypt, decrypt
from getpass import getpass
from os.path import getsize
from pathlib import Path
from secrets import token_bytes


AES_KEY_SIZE = 32       # 32 bytes = 256 bit key
CIPHERBLOCK = 16
CENC_IDENTIFIER = "cenc"
MAC_SIZE = 16


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


def dec_file(key, cipherfile, decfile):
    """Uses the private key to decrypt the file. The resulting plaintext
    file has the same name as the original file with removed .enc/.enx
    extension.

    :param key: The private key needed to decrypt the file.
    :type key: ``bitcash.wallet.PrivateKey`` or
    ``bitcash.wallet.PrivateKeyTestnet``
    :param cipherfile: The file to decrypt.
    :type cipherfile: ``pathlib.Path``
    :param decfile: The path to save the decrypted file.
    :type decfile: ``pathlib.Path``
    :raises DecryptionError: If a file with the intended decrypted file
    name already exists, or if the ciphertext file does not have a BoCA
    header, or if the size of the ciphertext file is not a multiple of
    the block size.
    :returns: The name of the decrypted file.
    :rtype: ``pathlib.Path``
    """

    if str(decfile)[-4:] == ".enc":
        dec_filename = Path(str(decfile)[:-4])
    elif str(decfile)[-4:] == ".enx":
        dec_filename = Path(str(decfile)[:-4])
    else:
        print(f"File does not end with .enc/.enx: {decfile}")
        sys.exit(1)

    if dec_filename.is_file():
        print("Warning: Cannot decrypt as %s already exists"
              % dec_filename)
        response = input("Do you wish to delete this file? (y/n): ")
        if response in ("Y", "y"):
            print("Deleting file.")
            dec_filename.unlink()
        else:
            raise DecryptionError(f"File named {str(dec_filename)} already " +
                                  "exists. Please move/delete before " +
                                  "attempting to decrypt.")

    if not dec_filename.parents[0].is_dir():
        Path(dec_filename.parents[0]).mkdir(parents=True, exist_ok=True)
        # print(f"Created folder: {dec_filename.parents[0]}")

    with open(cipherfile, 'rb') as file_in:
        header = file_in.read(len(CENC_IDENTIFIER) + 1)

        if header[:len(CENC_IDENTIFIER)] != b"cenc":
            raise DecryptionError("File does not have a BoCA header, "
                                  + "cannot decrypt. Header: 0x%s"
                                  % header.hex())
        # else:
        #     print("File has a CENC header, version number: %d"
        #           % header[len(CENC_IDENTIFIER)])

        # Get the length of the encrypted header containing the
        # encrypted symmetric key
        length = int.from_bytes(file_in.read(2), byteorder='big')
        encrypted_header = file_in.read(length)
        key_material = decrypt(key, encrypted_header)

        # If the length is not 32, then something is off!
        if len(key_material) != AES_KEY_SIZE+CIPHERBLOCK:
            raise DecryptionError(("Expecting %d bytes in symmetric key "
                                   + "material. Decryption failed: %s")
                                  % (AES_KEY_SIZE+CIPHERBLOCK,
                                     key_material.hex()))

        aes_key = key_material[:AES_KEY_SIZE]
        aes_nonce = key_material[AES_KEY_SIZE:AES_KEY_SIZE+CIPHERBLOCK]

        # Get the AES MAC/tag from the end of the file
        file_position = file_in.tell()
        file_in.seek(-MAC_SIZE, 2)
        aes_tag = file_in.read(MAC_SIZE)

        aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
        aes_cipher.update(header)

        file_in.seek(file_position)
        with open(dec_filename, "xb") as file_out:
            end_of_ciphertext = getsize(cipherfile)-MAC_SIZE
            while file_in.tell()+CIPHERBLOCK < end_of_ciphertext:
                cipher_block = file_in.read(CIPHERBLOCK)
                plain_block = aes_cipher.decrypt(cipher_block)
                file_out.write(plain_block)
            cipher_block = file_in.read(end_of_ciphertext - file_in.tell())
            plain_block = aes_cipher.decrypt(cipher_block)
            file_out.write(plain_block)

    aes_cipher.verify(aes_tag)

    # print("File successfully decrypted and verified (with symmetric key).")
    return dec_filename


def main():
    parser = ArgumentParser(description="Download files from the cloud " +
                            "and decrypt")
    parser.add_argument("--source", help="Location of the encrypted files",
                        type=str)
    parser.add_argument("--dest", help="Location of the decrypted files",
                        type=str)

    args = parser.parse_args()
    if not args.source:
        print("Please enter the location of the encrypted files with" +
              " the --source argument")
        sys.exit(1)
    if not args.dest:
        print("Please enter the location to save the decrypted files" +
              " with the --dest argument")
        sys.exit(1)

    pri_key = getpass("Please enter the private decryption key: ")
    
    print(f"Starting decrypting/restoring at {datetime.now()}")

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

    for file in source.rglob("*"):
        if not file.is_dir():
            dec_path = change_path(source, dest, file)
            retval = dec_file(pri_key, file, dec_path)

    print(f"Finished decrypting/restoring at {datetime.now()}")

if __name__ == "__main__":
    main()