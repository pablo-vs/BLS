from curve import (
    curve_order,
    G1,
    G2,
    pairing,
)
from curve.encoding import (
    encodePubKey,
    decodePubKey,
    encodePrivKey,
    decodePrivKey,
    encodeSignature,
    decodeSignature,
    ENDIANNESS
)
import random
from hashlib import sha256


# File where users' public keys are stored.
storagePubKeyFile = r"allPublicKeys.txt"


# Options for the menu
def menuText():
    print("1 -> Create a key pair")
    print("2 -> Sign document")
    print("3 -> Verify signature")
    print("4 -> Exit")
    opt = input("Enter your preferred option: ")
    try:
        opt = int(opt)
    except ValueError:
        opt = -1
    return opt


# Represents a message as a point which belongs to the eliptic curve
# Simplified version (probably insecure)
def hashToPoint(message):
    # TODO secure hashing function
    hint = int.from_bytes(sha256(message).digest(), byteorder=ENDIANNESS)
    h = hint % curve_order
    return G2 * h


# Generates both public and secret keys
def keyGen():
    sk = random.randint(0, curve_order)
    pk = G1 * sk
    return pk, sk


# Generates a signature of a file
def sign(message, privKey):
    H = hashToPoint(message)
    signature = privKey * H
    return signature


# Checks the signature of a file
def verify(msg, sig, pubKey):
    H = hashToPoint(msg)
    p1 = pairing(pubKey, H)
    p2 = pairing(G1, sig)
    return p1 == p2


# Processes the input/output when generating keys
def auxKeyGen():
    name = input("Type a name for the keypair: ")

    pk, sk = keyGen()

    privKeyPath = f"{name}_privkey.txt"
    pubKeyPath = f"{name}_pubkey.txt"

    try:
        with open(privKeyPath, "wb") as f:
            f.write(encodePrivKey(sk))
            f.close

        with open(pubKeyPath, "wb") as f:
            f.write(encodePubKey(pk))
            f.close

        with open(storagePubKeyFile, "a+") as f:
            f.write(" " + name + " " + encodePubKey(pk).decode("utf-8") + '\n')
            f.close

    except FileNotFoundError:
        print("An error occurred, please try again.")

    print("Your public key is in " + pubKeyPath)
    print("Your private key is in " + privKeyPath)


# Processes the input/output when signing a file
def auxSign():
    privKeyPath = input("Type the path of your private key file: ")
    filePath = input("Type the path of the document to sign: ")
    try:

        with open(filePath, 'rb') as fm, open(privKeyPath, "rb") as fp:
            message = fm.read()
            privKey = decodePrivKey(fp.read())
            signature = sign(message, privKey)

        signatureFilePath = filePath+".sig"

        with open(signatureFilePath, "wb") as f:
            f.write(encodeSignature(signature))

        print("The signature file is in " + signatureFilePath)
    except FileNotFoundError:
        print("File not found.")
    except ValueError:
        print("Private key file is corrupted.")


# Processes the input/output when verifying a signature
def auxVerify():
    pubKey = None
    pubKeyPath = input("Type the path of your public key file: ")
    signatureFilePath = input("Type the path of the signature file: ")
    filePath = input("Type the path of the document: ")
    try:
        with open(filePath, 'rb') as fm, \
             open(signatureFilePath, "rb") as fs, \
             open(pubKeyPath, "rb") as fp:

            pubKey = decodePubKey(fp.read())
            message = fm.read()
            signature = decodeSignature(fs.read())

        print("Please wait while we process your operation")
        res = verify(message, signature, pubKey)

        if res:
            print("The signature is correct.")
        elif res is False:
            print("The signature is incorrect.")
        elif res is None:
            print("Could not verify signature.")

    except FileNotFoundError:
        print("File not found.")
    except ValueError:
        print("File is corrupted")


def main():
    print("Welcome to the BLS signature ciphersuite.")
    print("The available options are: ")
    keep_going = True
    while keep_going:
        opt = menuText()

        while opt not in [1, 2, 3, 4]:
            print("Please select a valid option.")
            opt = menuText()

        if opt == 4:
            keep_going = False
        elif opt == 1:      # Generate keys
            auxKeyGen()
        elif opt == 2:      # Sign
            auxSign()
        else:               # Verify
            auxVerify()


if __name__ == "__main__":
    main()
