#Import curves elements
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
from hashlib import sha256

#File where user's public keys are stored. It works similar to a DB.
storagePubKeyFile = r"allPublicKeys.txt"

#Options for the menu
def menuText():
  print("1 -> Crear un par de firmas")
  print("2 -> Firmar un documento")
  print("3 -> Comprobar la firma de un documento")
  print("4 -> Salir")
  opt = input("Introduzca la opción: ")
  try:
    opt = int(opt)
  except ValueError as e:
      opt = -1
  return opt

#Adds a new user and its public key to the system DB
def addUserPub(name, pubKey):
  try:
      fo = open(storagePubKeyFile, "a")
      fo.write(" " + name + " " + pubKey + "\n")
      fo.close()
  except FileNotFoundError:
      print("Problema con la Base de Datos. Consulte al administrador.")
      return

#Returns True if user's name is in the DB. False if not.
def isUser(name):
  try:
      fo = open(storagePubKeyFile, "r")
      ret = True
      if " "+name+" " not in fo.read():
          ret = False
      fo.close()
      return ret
  except FileNotFoundError:
      fo = open(storagePubKeyFile, "w")
      fo.close()
      return False

# Functions to encode and decode data to base64
# Improves readability of the files

#Returns the public key encoded in base64
def encodePubKey(pk):
    # TODO point compression: the coded version could be shorter 
    #Instead of storing both x and y, it could be stored just x and then calculate y from the curve equation
    x, y = pk
    return base64.b64encode(x.val.to_bytes(48, byteorder='little')
            + y.val.to_bytes(48, byteorder='little'))

#Returns the public key decoded from base64
def decodePubKey(pkStr):
    byte = base64.b64decode(pkStr)
    x = FQ(int.from_bytes(byte[:48], byteorder='little'))
    y = FQ(int.from_bytes(byte[48:], byteorder='little'))
    return BaseCurve(x,y)

#Returns the private key encoded in base64
def encodePrivKey(sk):
    return base64.b64encode(sk.to_bytes(32, byteorder='little'))

#Returns the private key decoded from base64
def decodePrivKey(skStr):
    return int.from_bytes(base64.b64decode(skStr), byteorder='little')

#Returns the signature encoded in base64
def encodeSignature(sig):
    x, y = sig
    x0, x1 = x.val[0].val, x.val[1].val
    y0, y1 = y.val[0].val, y.val[1].val
    return base64.b64encode(x0.to_bytes(48, byteorder='little')
            + x1.to_bytes(48, byteorder='little')
            + y0.to_bytes(48, byteorder='little')
            + y1.to_bytes(48, byteorder='little'))

#Returns the signature decoded from base64
def decodeSignature(sigStr):
    byte = base64.b64decode(sigStr)
    x0 = int.from_bytes(byte[:48], byteorder='little')
    x1 = int.from_bytes(byte[48:96], byteorder='little')
    y0 = int.from_bytes(byte[96:144], byteorder='little')
    y1 = int.from_bytes(byte[144:], byteorder='little')
    x = FQ2([x0, x1])
    y = FQ2([y0, y1])
    return ExtCurve(x,y)

#Represents a message as a point which belongs to the eliptic curve
#Simplified version to make it work quicker
def hashToPoint(message):
    # TODO secure hashing function
    hint = int.from_bytes(sha256(message).digest(), byteorder='little')
    h = hint % curve_order
    return G2 * h

#It generates both public and private keys and storage the public key on the DB
#Returns True on success and the two keys
def keyGenerator(name):
  sk = random.randint(0, curve_order)
  pk = G1 * sk  
  privKeyPath = f"{name}_privkey.txt"
  try:
      with open(privKeyPath, "wb") as f:
          f.write(encodePrivKey(sk))
          f.close

      pubKeyPath = f"{name}_pubkey.txt"
      with open(pubKeyPath, "wb") as f:
          f.write(encodePubKey(pk))
          f.close

      with open(storagePubKeyFile, "a+") as f:
          f.write(" " + name + " ")
          f.write(encodePubKey(pk).decode("utf-8"))
          f.write('\n')
          f.close
      return (True, pubKeyPath, privKeyPath)
  except FileNotFoundError:
      print("Ha habido un error generando los archivos que contienen las claves. Vuelva a intentarlo.")

#Generates a signature of a file
#Returns True on success and the signature file path
def signFile(filePath, privKey):
  with open(filePath, 'rb') as f:
      message = f.read()

  H = hashToPoint(message)
  signature = privKey * H
    
  signatureFilePath = filePath+".sig"

  with open(signatureFilePath, "wb") as f:
      f.write(encodeSignature(signature))

  return (True, signatureFilePath)

#Checks the signature of a file
#Returns True if the signature is valid
def verifySignature(filePath, signatureFilePath, pubKey):
  try:
      with open(filePath, 'rb') as f:
          message = f.read()

      H = hashToPoint(message)
  

      with open(signatureFilePath, "rb") as f:
          signature = decodeSignature(f.read())
      p1 = pairing(pubKey, H)
      p2 = pairing(G1, signature)
      return p1 == p2	  
  except FileNotFoundError:
      print("No se ha encontrado el archivo")
      return


#Processes the input/output when generating keys
def auxKeyGenerator():
    name = input("Escriba su nombre: ")
    isUserVar = isUser(name)
    if isUserVar:
      print("Este usuario ya tiene su par de claves")
      return
    elif not isUserVar:
      myTuple = keyGenerator(name)    
      if myTuple[0]:
          print("Su clave pública se aloja en: " + myTuple[1])
          print("Su clave privada se aloja en: " + myTuple[2])
      else:
          print("Ha habido un error generando las claves, vuelva a intentarlo.")
   
	

#Processes the input/output when signing a file
def auxSignFile():
  privKeyPath = input("Escriba la ruta del fichero donde está su clave privada: ")
  filePath = input("Escriba la ruta del fichero que quiere firmar: ")

  fo = open(privKeyPath, "rb")
  privKey = decodePrivKey(fo.read())
  fo.close()

  myTuple = signFile(filePath, privKey)  
  if myTuple[0]:
    print("El documento firmado se encuentra en: " + myTuple[1])
  else: 
    print("Ha habido un error firmando el fichero, vuelva a intentarlo.")

#Processes the input/output when verifying a signature
def auxVerifySignature():
  print("Escoja una opción: ")
  print(" a. Si el firmante es usuario del sistema, escriba su nombre.")
  print(" b. Si no, escriba la ruta donde se almacena su clave pública.")
  opt = input()

  pubKey = None    
  if opt == "a":
    name = input("Escriba su nombre: ")
    if isUser(name):
      fo = open(storagePubKeyFile, "r")
      for line in fo:
        line = line.split()
        if line[0] == name:
          pubKey = decodePubKey(line[1].encode("utf-8"))
          break
      
    elif False:
      print("Su usuario no existe.")
      return
  
  elif opt == "b":
    pubKeyPath = input("Escriba la ruta donde se almacena la clave pública del firmante: ")
    fo = open(pubKeyPath, "rb")
    pubKey = decodePubKey(fo.read())
    fo.close()

  else:
    print("Opción no válida.")
    return

  signatureFilePath = input("Escriba la ruta de la FIRMA a verificar (el documento .sig): ")
  filePath = input("Escriba la ruta del DOCUMENTO original que se ha firmado: ")

  if verifySignature(filePath, signatureFilePath, pubKey):
    print("La firma es correcta.")
  elif False: 
    print("La firma no es correcta.")


def main():
  print("Bienvenido al trabajo de CTC sobre curvas elípticas BLS. Se puede: ")
  exit = False
  while not exit:
    opt = menuText()
  
    while opt not in [1,2,3,4]:
      print("Por favor, escoja una opción válida.")
      opt = menuText()
  
    if opt == 4:
        exit = True
    elif opt == 1: #Crear firmas
      auxKeyGenerator()
    elif opt == 2: #Firmar doc
      auxSignFile()
    else: #check firma
      auxVerifySignature()
    
    if exit:
        return 0

if __name__ == "__main__":
    main()
