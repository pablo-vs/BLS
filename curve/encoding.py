import base64
from math import ceil

from curve import (
    curve_order,
    FQ,
    FQ2,
    BLS12_381_FQ as BaseCurve,
    BLS12_381_FQ2 as ExtCurve
)


#### Encoding properties ####

ENDIANNESS = 'big'
BIT_COMPRESSED = 1<<7
BIT_INF = 1<<6
BIT_SIGN = 1<<5

POINT_COMPRESSION = True

PRIVKEY_SIZE = 32
FQ_SIZE = 48

def PUBKEY_SIZE(comp):
    return FQ_SIZE*(1 if comp else 2)

def SIGNATURE_SIZE(comp):
    return 2*FQ_SIZE*(1 if comp else 2)

def sign_F(e):
    return 1 if e.val > (F.order()-1)//2 else 0

def sign_F2(e):
    if e.val[1] == 0:
        return sign_F(e.val[0])
    elif e.val[1] > (FQ2.char()-1)//2:
        return 1
    else:
        return 0

def metadata_bits(c,i,s):
    return c*BIT_COMPRESSED + i*BIT_INF + s*BIT_SIGN

def is_comp(b):
    return b & BIT_COMPRESSED != 0

def is_inf(b):
    return b & BIT_INF != 0

def sign(b):
    return (b & BIT_SIGN) // BIT_SIGN


# Functions to encode and decode data to base64
# Improves readability of the files

#Returns the public key encoded in base64
def encodePubKey(pk):
    #print(pk)
    x, y = pk

    if pk.is_infinite():
        x_bytes = bytes(FQ_SIZE)
    else:
        x_bytes = x.val.to_bytes(FQ_SIZE, byteorder=ENDIANNESS)

    if POINT_COMPRESSION:
        y_bytes = b''
    elif pk.is_infinite():
        y_bytes = bytes(FQ_SIZE)
    else:
        y_bytes = y.val.to_bytes(FQ_SIZE, byteorder=ENDIANNESS)

    c_bit = 1 if POINT_COMPRESSION else 0
    i_bit = 1 if pk.is_infinite() else 0
    if c_bit*i_bit == 0:
        s_bit = 0
    else:
        s_bit = sign_F(y)

    first_byte = x_bytes[0] + metadata_bits(c_bit, i_bit, s_bit)

    tot_bytes = bytes([first_byte]) + x_bytes[1:] + y_bytes
    return base64.b64encode(tot_bytes)

#Returns the public key decoded from base64
def decodePubKey(pkStr):
    byte = base64.b64decode(pkStr)

    metadata = byte[0]
    if is_inf(metadata):
        return BaseCurve()

    byte = bytes([byte[0] & ((1<<5)-1)]) + byte[1:]

    if len(byte) != PUBKEY_SIZE(is_comp(metadata)):
        raise ValueError("It seems like your public key file is corrupted")

    if is_comp(metadata):
        x = FQ(int.from_bytes(byte, byteorder=ENDIANNESS))
        
        y2 = x**3 + 4
        if not y2.is_quadratic():
            raise ValueError("It seems like your public key file is corrupted")
        y = y2.sqrt()[sign(metadata)]

    else:
        x = FQ(int.from_bytes(byte[:FQ_SIZE], byteorder=ENDIANNESS))
        y = FQ(int.from_bytes(byte[FQ_SIZE:], byteorder=ENDIANNESS))

    try:
        #print(BaseCurve(x,y))
        return BaseCurve(x,y)
    except ValueError as e:
        raise ValueError("It seems your public key file is corrupted:,", e)


#Returns the private key encoded in base64
def encodePrivKey(sk):
    return base64.b64encode(sk.to_bytes(PRIVKEY_SIZE, byteorder=ENDIANNESS))

#Returns the private key decoded from base64
def decodePrivKey(skStr):
    skStr = skStr.strip(b' \n')
    if len(skStr) > 4*ceil(PRIVKEY_SIZE/3):
        raise ValueError("It seems like your private key file is corrupted.")
    res = int.from_bytes(base64.b64decode(skStr), byteorder=ENDIANNESS)
    if res < 0 or res > curve_order:
        raise ValueError("It seems like your private key file is corrupted.")
    return res
    

#Returns the signature encoded in base64
def encodeSignature(sig):
    #print(sig)
    x, y = sig

    if sig.is_infinite():
        x_bytes = bytes(2*FQ_SIZE)
    else:
        x0, x1 = x.val[0].val, x.val[1].val
        x_bytes = (x0.to_bytes(FQ_SIZE, byteorder=ENDIANNESS)
                    + x1.to_bytes(FQ_SIZE, byteorder=ENDIANNESS))

    if POINT_COMPRESSION:
        y_bytes = b''
    elif sig.is_infinite():
        y_bytes = bytes(2*FQ_SIZE)
    else:
        y0, y1 = y.val[0].val, y.val[1].val
        y_bytes = (y0.to_bytes(FQ_SIZE, byteorder=ENDIANNESS)
                    + y1.to_bytes(FQ_SIZE, byteorder=ENDIANNESS))

    c_bit = 1 if POINT_COMPRESSION else 0
    i_bit = 1 if sig.is_infinite() else 0
    if c_bit == 0 or i_bit == 1:
        s_bit = 0
    else:
        s_bit = sign_F2(y)

    #print(s_bit)
    #print(sign_F2(y))
    #print(y)

    first_byte = x_bytes[0] + metadata_bits(c_bit, i_bit, s_bit)

    tot_bytes = bytes([first_byte]) + x_bytes[1:] + y_bytes
    return base64.b64encode(tot_bytes)



#Returns the signature decoded from base64
def decodeSignature(sigStr):
    byte = base64.b64decode(sigStr)

    metadata = byte[0]
    if is_inf(metadata):
        # TODO check error
        return ExtCurve()

    byte = bytes([byte[0] & ((1<<5)-1)]) + byte[1:]

    if len(byte) != SIGNATURE_SIZE(is_comp(metadata)):
        raise ValueError("It seems like the signature file is corrupted")

    x0 = int.from_bytes(byte[:FQ_SIZE], byteorder=ENDIANNESS)
    x1 = int.from_bytes(byte[FQ_SIZE:2*FQ_SIZE], byteorder=ENDIANNESS)
    x = FQ2([x0, x1])

    if is_comp(metadata):
        y2 = x**3 + FQ2([4,4])
        if not y2.is_quadratic():
            raise ValueError("It seems like the signature file is corrupted")
        ys = y2.sqrt()
        if sign(metadata) == sign_F2(ys[0]):
            y = ys[0]
        else:
            y = ys[1]

        #print(y)
        #print(sign(metadata))
        #print(sign_F2(y))

    else:
        y0 = int.from_bytes(byte[2*FQ_SIZE:3*FQ_SIZE], byteorder=ENDIANNESS)
        y1 = int.from_bytes(byte[3*FQ_SIZE:], byteorder=ENDIANNESS)
        y = FQ2([y0, y1])

    try:
        #print(ExtCurve(x,y))
        return ExtCurve(x,y)
    except ValueError as e:
        raise ValueError("It seems like the signature file is corrupted:,", e)

