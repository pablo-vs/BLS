from curve import (
    curve_order,
    G1,
    G2,
    pairing,
    FQ,
    FQ2,
    BLS12_381_FQ as BaseCurve,
    BLS12_381_FQ2 as ExtCurve
)
import random
import base64



storagePubKeyFile = r"allPublicKeys.txt"

def menuText():
  print("1 -> Crear un par de firmas")
  print("2 -> Firmar un documento")
  print("3 -> Comprobar la firma de un documento")
  print("4 -> Salir")
  opt = input("Introduzca la opción:")
  opt = int(opt)
  return opt

def addUserPub(name, pubKey):
  fo = open(storagePubKeyFile, "a")

  fo.write(name + " " + pubKey + "\n")

  fo.close()

def isUser(name):
     fo = open(storagePubKeyFile, "r")
     ret = True
     if name not in fo.read():
       ret = False

     fo.close()
     return ret


# Functions to encode and decode data to base64
# Improves readability

def encodePubKey(pk):
    # TODO point compression
    x, y = pk
    return base64.encodebytes(x.val.to_bytes(48, byteorder='little')
            + y.val.to_bytes(48, byteorder='little'))

def decodePubKey(pkStr):
    byte = base64.decodebytes(pkStr)
    x = FQ(int.from_bytes(byte[:48], byteorder='little'))
    y = FQ(int.from_bytes(byte[48:], byteorder='little'))
    return BaseCurve(x,y)

def encodePrivKey(sk):
    return base64.encodebytes(sk.to_bytes(32, byteorder='little'))

def decodePrivKey(skStr):
    return int.from_bytes(base64.decodebytes(skStr), byteorder='little')

def encodeSig(sig):
    x, y = sig
    x0, x1 = x.val[0].val, x.val[1].val
    y0, y1 = y.val[0].val, y.val[1].val
    return base64.encodebytes(x0.to_bytes(48, byteorder='little')
            + x1.to_bytes(48, byteorder='little')
            + y0.to_bytes(48, byteorder='little')
            + y1.to_bytes(48, byteorder='little'))

def decodeSig(sigStr):
    byte = base64.decodebytes(sigStr)
    x0 = int.from_bytes(byte[:48], byteorder='little')
    x1 = int.from_bytes(byte[48:96], byteorder='little')
    y0 = int.from_bytes(byte[96:144], byteorder='little')
    y1 = int.from_bytes(byte[144:], byteorder='little')
    x = FQ2([x0, x1])
    y = FQ2([y0, y1])
    return ExtCurve(x,y)


def hashToPoint(message):
    # TODO secure hashing function
    h = hash(message) % curve_order
    return G2 * h

def keyGenerator(name):
  sk = random.randint(0, curve_order)
  pk = G1 * sk
  
  privKeyPath = f"{name}_privkey.txt"
  with open(privKeyPath, "wb") as f:
      f.write(encodePrivKey(sk))

  pubKeyPath = f"{name}_pubkey.txt"
  with open(pubKeyPath, "wb") as f:
      f.write(encodePubKey(pk))
      print(encodePubKey(pk))

  return (True, pubKeyPath, privKeyPath)


def signFile(filePath, privKey):
  with open(filePath, 'rb') as f:
      message = f.read()

  H = hashToPoint(message)
  signature = privKey * H
    
  signatureFilePath = filePath+".sig"

  with open(signatureFilePath, "wb") as f:
      f.write(encodeSig(signature))

  return (True, signatureFilePath)


def verifySignature(filePath, signatureFilePath, pubKey):
  with open(filePath, 'rb') as f:
      message = f.read()

  H = hashToPoint(message)

  with open(signatureFilePath, "rb") as f:
      signature = decodeSig(f.read())

  return pairing(pubKey, H) == pairing(G1, signature)


def auxKeyGenerator():
    name = input("Escriba su nombre:")
    if isUser(name):
      print("Este usuario ya tiene su par de claves")
      return
    else:
      myTuple = keyGenerator(name)
    
    if myTuple[0]:
      print("Su clave pública se aloja en: " + myTuple[1])
      print("Su clave privada se aloja en: " + myTuple[2])
    else:
      print("Ha habido un error generando las claves, vuelva a intentarlo.")
    
def auxSignFile():

  privKeyPath = input("Escriba la ruta del fichero donde está su clave privada: ")
  filePath = input("Escriba la ruta del fichero que quiere firmar: ")

  fo = open(privKeyPath, "rb")
  privKey = decodePrivKey(fo.read())
  fo.close()

  #Se pasa la ruta del fichero a firmar y la clave privada
  #Devuelve true/false y el path al documento firmado
  myTuple = signFile(filePath, privKey)
  
  if myTuple[0]:
    print("El documento firmado se encuentra en: " + myTuple[1])
  else: 
    print("Ha habido un error firmando el fichero, vuelva a intentarlo.")


def auxVerifySignature():
  print("Escoja una opción: ")
  print(" a. Si es usuario del sistema, escriba su nombre")
  print(" b. Si no, escriba la ruta donde se almacena su clave pública.")
  opt = input()

  if opt == "a":
    name = input("Escriba su nombre:")
    if isUser(name):
      fo = open(storagePubKeyFile, "rb")
      for line in fo:
        line = line.split()
        if line[0] == name:
          pubKey = decodePubKey(line[1])
          break
      
    else:
      print("Su usuario no existe.")
      return
  
  elif opt == "b":
    pubKeyPath = input("Escriba la ruta donde se almacena su clave pública: ")
    fo = open(pubKeyPath, "rb")
    pubKey = decodePubKey(fo.read())
    fo.close()

  else:
    print("Opción no válida.")
    return

  signatureFilePath = input("Escriba la ruta de la firma a verificar:")
  filePath = input("Escriba la ruta del documento firmado:")

  if verifySignature(filePath, signatureFilePath, pubKey):
    print("La firma es correcta.")
  else: 
    print("La firma no es correcta.")


def main():
  print("Bienvenido al trabajo de CTC sobre curvas elípticas BLS. Se puede:")
  while 1:
    opt = menuText()
  
    while opt not in [1,2,3,4]:
      print("Escoja una opción válida:")
      opt = menuText()
  
    if opt == 4:
        return 0
    elif opt == 1: #Crear firmas
      auxKeyGenerator()
    elif opt == 2: #Firmar doc
      auxSignFile()
    else: #check firma
      auxVerifySignature()

if __name__ == "__main__":
    main()
