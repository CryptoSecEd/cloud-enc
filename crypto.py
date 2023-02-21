"""This contains all the cryptography related functions for BoCA
"""

import hmac
import sys

from base64 import b64decode, b64encode
from getpass import getpass
from hashlib import pbkdf2_hmac, sha256
from os.path import getsize
from pathlib import Path
from secrets import token_bytes

from bitcash.wallet import wif_to_key, PrivateKey
from Cryptodome.Cipher import AES
from ecies import encrypt, decrypt
from eth_account import account
from web3 import Web3

import boca

AES_KEY_SIZE = 32       # 32 bytes = 256 bit key
BCH_TO_SAT_MULTIPLIER = 100000000
BOCA_IDENTIFIER = b"boca"
CIPHERBLOCK = 16
HASH_ITERATIONS = 1000000
MAC_SIZE = 16

SUPPORTED_CHAINS = ["BCH", "tBCH", "ETH", "tETH"]


class DecryptionError(Exception):
    """ Raised whenever a file does not decrypt correctly
    """


def dec_file(key, filename, chain):
    """Uses the private key to decrypt the file. The resulting plaintext
    file has the same name as the original file with a ".dec" extension.

    :param key: The private key needed to decrypt the file.
    :type key: ``bitcash.wallet.PrivateKey`` or
    ``bitcash.wallet.PrivateKeyTestnet``
    :param filename: The file to decrypt.
    :type filename: ``pathlib.Path``
    :raises DecryptionError: If a file with the intended decrypted file
    name already exists, or if the ciphertext file does not have a BoCA
    header, or if the size of the ciphertext file is not a multiple of
    the block size.
    :returns: The name of the decrypted file.
    :rtype: ``pathlib.Path``
    """

    if chain in ("ETH",  "tETH"):
        key = PrivateKey.from_bytes(key.privateKey)

    dec_filename = Path(str(filename) + ".dec")

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
    with open(filename, 'rb') as file_in:
        header = file_in.read(len(BOCA_IDENTIFIER) + 1)

        if header[:len(BOCA_IDENTIFIER)] == b"boca":
            print("File has a BoCA header, version number: %d"
                  % header[len(BOCA_IDENTIFIER)])
        else:
            raise DecryptionError("File does not have a BoCA header, "
                                  + "cannot decrypt. Header: 0x%s"
                                  % header.hex())
        # Get the length of the encrypted header containing the
        # encrypted symmetric key
        length = int.from_bytes(file_in.read(2), byteorder='big')
        encrypted_header = file_in.read(length)

        key_material = decrypt(key.to_hex(), encrypted_header)
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
            end_of_ciphertext = getsize(filename)-MAC_SIZE
            while file_in.tell()+CIPHERBLOCK < end_of_ciphertext:
                cipher_block = file_in.read(CIPHERBLOCK)
                plain_block = aes_cipher.decrypt(cipher_block)
                file_out.write(plain_block)
            cipher_block = file_in.read(end_of_ciphertext - file_in.tell())
            plain_block = aes_cipher.decrypt(cipher_block)
            file_out.write(plain_block)

    aes_cipher.verify(aes_tag)

    print("File successfully decrypted and verified (with symmetric key).")
    return dec_filename


def derive_key_dec(salt):
    """Take the salt as argument, ask the user to input the password and
    generate the key.

    :param salt: The salt that is hashed with the password.
    :type salt: ``bytes``
    :returns: A 32 byte key
    :rtype: ``bytes``
    """
    password = getpass("Enter password to access private key(s): ")

    key = pbkdf2_hmac('sha256', bytes(password, 'utf-8'), salt,
                      HASH_ITERATIONS)

    return key


def derive_key_enc():
    """Ask the user to enter a password, then ask them to repeat and
    ensure the same value is entered again.

    :returns: A tuple containing the salt and key.
    :rtype: ``tuple``
    """

    pass1 = "X"        # These are just two different values
    pass2 = "Y"        # to force the first iteration of the while loop
    while pass1 != pass2:
        pass1 = getpass("Enter password to encrypt private key(s): ")
        pass2 = getpass("Verify password: ")
    print("Passwords match")
    salt = token_bytes(CIPHERBLOCK)

    key = pbkdf2_hmac('sha256', bytes(pass1, 'utf-8'), salt, HASH_ITERATIONS)

    return (salt, key)


def enc_file(pubkey, filename):
    """Use the public key to encrypt the file. The ciphertext filename
    is just the plaintext filename with an added ".enc" extension.
    The file contains:
    'boca1'+<len enc key>+<public key encrypted random key>
    +<encrypted file>+<MAC>
    The '1' after 'boca' is the version number
    Some links I've used for reference:
    https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html
    https://pypi.org/project/eciespy/
    https://nitratine.net/blog/post/python-gcm-encryption-tutorial/
        #encryption-planning

    :param pubkey: The public key used to encrypt the file.
    :type pubkey: ``str``
    :param filename: The name of the plaintext file.
    :type filename: ``pathlib.Path``
    :returns: The ciphertext filename.
    :rtype: ``pathlib.Path``
    """

    boc_version = 1
    header = BOCA_IDENTIFIER+bytes([boc_version])

    aes_key = token_bytes(AES_KEY_SIZE)
    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    aes_cipher.update(header)
    encrypted_key = encrypt(pubkey, aes_key+aes_cipher.nonce)

    # enc_filename = filename+'.enc'
    enc_filename = Path(str(filename) + '.enc')
    with open(enc_filename, 'xb') as file_out:
        file_out.write(header)
        file_out.write((len(encrypted_key)).to_bytes(2, byteorder='big'))
        file_out.write(encrypted_key)

        with open(filename, 'rb') as file_in:
            plain_block = file_in.read(CIPHERBLOCK)
            while plain_block != b'':
                cipher_block = aes_cipher.encrypt(plain_block)
                file_out.write(cipher_block)
                plain_block = file_in.read(CIPHERBLOCK)
            tag = aes_cipher.digest()
            file_out.write(tag)
    return enc_filename


def enc_keys(data, filename):
    """Encrypt the dictionary of keys with a password and save to file.

    :param data: A dictionary of private (blockchain) keys.
    :type data: ``dict``
    :param filename: Name of file to write the data to
    :type filename: ``pathlib.Path``
    :rtype: ``int``
    """
    boc_version = 1
    header = BOCA_IDENTIFIER+bytes([boc_version])
    (salt, aes_key) = derive_key_enc()
    parsed_data = parse_data(data)
    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    aes_cipher.update(header)
    encrypted_data, tag = aes_cipher.encrypt_and_digest(parsed_data)
    combined_data = bytearray(bytes("Salt____", 'utf-8'))
    combined_data.extend(salt)
    combined_data.extend(aes_cipher.nonce+tag)
    combined_data.extend(encrypted_data)
    with open(filename, 'wb') as file_out:
        file_out.write(b64encode(combined_data))
    return 0


def hmac_file(key, filename):
    """Calculates the HMAC of a file using SHA-256

    :param key: Secret key used in calculating the HMAC
    :type key: ``bytes``
    :param filename: Calculate the HMAC of this file.
    :type filename: ``pathlib.Path``
    :returns: The calculated HMAC
    :rtype: ``str``
    """
    hmac_hash = hmac.new(key, digestmod=sha256)
    try:
        with open(filename, "rb") as file_in:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: file_in.read(4096), b""):
                hmac_hash.update(byte_block)
            return hmac_hash.hexdigest()
    except IOError:
        print("Unable to open file %s" % filename)
        sys.exit(1)


def key_manager(keyfile, chain='ALL', check_balance=False):
    """Attempt to decrypt the private key file with the user-supplied password.

    :param keyfile: File containing encrypted private keys.
    :type keyfile: ``pathlib.Path``
    :param chain: Specify the blockchain private key needed or 'ALL' for
    all keys contained in the file.
    :type chain: ``str``
    :param check_balance: If true then print the balance of each address
    :type check_balance: ``bool``
    :returns: Dictionary of keys.
    :rtype: ``dict``
    """

    boc_version = 1
    header = BOCA_IDENTIFIER + bytes([boc_version])

    try:
        with open(keyfile, 'rb') as file_in:
            encoded_ciphertext = file_in.read()
    except IOError:
        print("Could not open file '%s'" % keyfile)
        print("Please specify private key file with the --keyfile argument")
        sys.exit(1)

    decoded_ciphertext = b64decode(encoded_ciphertext)
    salt_label = decoded_ciphertext[0:8]
    if salt_label != bytes("Salt____", "utf-8"):
        print("Incorrect format of private key file")
        sys.exit(1)

    salt = decoded_ciphertext[8:8+CIPHERBLOCK]
    aes_key = derive_key_dec(salt)
    aes_nonce = decoded_ciphertext[8+CIPHERBLOCK:8+2*CIPHERBLOCK]
    aes_tag = decoded_ciphertext[8+2*CIPHERBLOCK:8+3*CIPHERBLOCK]
    encrypted_private_key = decoded_ciphertext[8+3*CIPHERBLOCK:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
    cipher.update(header)

    try:
        plaintext = cipher.decrypt_and_verify(encrypted_private_key, aes_tag)
    except ValueError:
        print("Decryption failed. Check your password and/or make sure data" +
              " not corrupt.")
        sys.exit(1)

    privatekeys = {}

    # Structure of each key is:
    # (8-bytes) length
    # (8-bytes) ticker (with padding spaces as needed)
    # (variable) key.
    while len(plaintext):
        section_length = int(plaintext[0:8])
        if (section_length > len(plaintext) or section_length < 1):
            print("Error! Invalid formatting of stored private keys.")
            sys.exit(1)
        ticker = plaintext[8:16].decode('utf-8')
        ticker = ticker.rstrip()

        if chain == 'tETH':
            chain = 'ETH'     # Testnet and mainnet ETH use the same key

        if chain in ('ALL', ticker):
            privatekeys[ticker] = parse_key(ticker,
                                            plaintext[16:section_length]
                                            .decode('utf-8'), check_balance)
        # Remove processed text to make sure the loop terminates
        plaintext = plaintext[section_length:]
    if len(privatekeys) == 0:
        print("No keys for chain %s obtained from keyfile" % chain)
        sys.exit(1)
    return privatekeys


def parse_data(data):
    """Takes a dictionary of keys and produces a single byte array,
    ready to be encrypted.

    :param data: Dictionary of (blockchain) private keys
    :type data: ``dict``
    :returns: Binary blob of encoded keys
    :rtype: ``bytes``
    """
    text = ""
    tickers = ["BCH", "tBCH", "ETH"]

    for tic in tickers:
        if tic in data.keys():
            add_key = tic.ljust(8, " ") + data[tic]
            # Adding 8 for the length value itself
            text = text + str(len(add_key) + 8).rjust(8, "0") + add_key
    return bytes(text, "utf-8")


def parse_key(chain, raw_key, check_balance):
    """Take the raw decrypted text from the private key file and parse
    it to get the cryptocurrency private keys in a dictionary.

    :param chain: The blockchain type of key
    :type chain: ``str``
    :param raw_key: The key in raw binary form
    :type raw_key: ``bytes``
    :param check_balance: If true, then print the balance of the address
    :type check_balance: ``bool``
    :returns: The private key
    :rtype: ``bitcash.wallet.PrivateKey`` or
    ``bitcash.wallet.PrivateKeyTestnet`` or
    ``eth_account.signers.local.LocalAccount``
    """

    key = ""
    if chain == 'BCH':
        key = wif_to_key(raw_key)
        print("BCH address: %s" % key.address)
        if check_balance:
            balance = boca.blockchain.get_balance_local(key.address, chain)
            print("BCH balance: %.8f BCH or %s satoshi"
                  % (balance/BCH_TO_SAT_MULTIPLIER, balance))
    elif chain == 'tBCH':
        print("Testnet BCH API currently not operating.")
        """
        key = wif_to_key(raw_key)
        print("(testnet) BCH address: %s" % key.address)
        if check_balance:
            balance = boca.blockchain.get_balance_local(key.address,
                                                        chain)
            print("(testnet) BCH balance: %.8f BCH or %s satoshi"
                  % (balance/BCH_TO_SAT_MULTIPLIER, balance))
        """
    elif chain == 'ETH':
        from boca.config import INFURA_URL_MAINNET, INFURA_URL_TESTNET
        w3main = Web3(Web3.HTTPProvider(INFURA_URL_MAINNET))
        w3test = Web3(Web3.HTTPProvider(INFURA_URL_TESTNET))
        if not w3main.isConnected():
            print("Cannot connect to Web3 provider: %s"
                  % boca.config.INFURA_URL_MAINNET)
            sys.exit(1)
        if not w3test.isConnected():
            print("Cannot connect to Web3 provider: %s"
                  % boca.config.INFURA_URL_TESTNET)
            sys.exit(1)
        key = account.Account.from_key(bytes.fromhex(raw_key))
        print("ETH Address: %s" % key.address)
        if check_balance:
            balance_main = w3main.eth.getBalance(key.address)
            print("ETH Balance: %.9f eth or %.2f gwei"
                  % (w3main.fromWei(balance_main, 'ether'),
                     w3main.fromWei(balance_main, 'gwei')))
            balance_test = w3test.eth.getBalance(key.address)
            print("(testnet) ETH Balance: %.9f eth or %.2f gwei"
                  % (w3test.fromWei(balance_test, 'ether'),
                     w3test.fromWei(balance_test, 'gwei')))
    else:
        print("Unknown chain: %s" % chain)
        sys.exit(1)
    return key
