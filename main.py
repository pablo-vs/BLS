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



#Represents a message as a point which belongs to the eliptic curve
#Simplified version to make it work quicker
def hashToPoint(message):
    # TODO secure hashing function
    hint = int.from_bytes(sha256(message).digest(), byteorder=ENDIANNESS)
    h = hint % curve_order
    return G2 * h

#It generates both public and private keys and storage the public key on the DB
#Returns True on success and the two keys
def keyGenerator(name):
  sk = random.randint(0, curve_order)
  pk = G1 * sk  
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
	
      return (True, pubKeyPath, privKeyPath)

  except FileNotFoundError:
      print("Ha habido un error generando los archivos que contienen las claves. Vuelva a intentarlo.")

#Generates a signature of a file
#Returns True on success and the signature file path
def signFile(filePath, privKey):
  try:
      with open(filePath, 'rb') as f:
          message = f.read()

      H = hashToPoint(message)
      signature = privKey * H

      signatureFilePath = filePath+".sig"

      with open(signatureFilePath, "wb") as f:
          f.write(encodeSignature(signature))
	  

      return (True, signatureFilePath)

  except (FileNotFoundError, ValueError):
      return (False, "")


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
  except ValueError:
      print("Archivo dañado o incorrecto")

  return None


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
  try:
    fo = open(privKeyPath, "rb")
    privKey = decodePrivKey(fo.read())
    fo.close()

    myTuple = signFile(filePath, privKey)  
    if myTuple[0]:
      print("El documento firmado se encuentra en: " + myTuple[1])
    else: 
      print("Ha habido un error firmando el fichero, vuelva a intentarlo.")
  except FileNotFoundError:
    print("La ruta no se encuentra")
  except ValueError:
    print("Archivo dañado o incorrecto")

#Processes the input/output when verifying a signature
def auxVerifySignature():
  print("Escoja una opción: ")
  print(" a. Si el firmante es usuario del sistema, escriba su nombre.")
  print(" b. Si no, escriba la ruta donde se almacena su clave pública.")
  opt = input()

  pubKey = None    
  if opt == "a":
    name = input("Escriba su nombre: ")
    isUserVar = isUser(name)
    if isUserVar:
      fo = open(storagePubKeyFile, "r")
      for line in fo:
        line = line.split()
        if line[0] == name:
          pubKey = decodePubKey(line[1].encode("utf-8"))
          break
      
    elif not isUserVar:
      print("Su usuario no existe.")
      return
  
  elif opt == "b":
    pubKeyPath = input("Escriba la ruta donde se almacena la clave pública del firmante: ")
    try:
    	fo = open(pubKeyPath, "rb")
    	pubKey = decodePubKey(fo.read())
    	fo.close()

    except FileNotFoundError:
      print("No se ha encontrado el archivo")
      return
    except ValueError:
      print("Archivo dañado o incorrecto")
      return

  else:
    print("Opción no válida.")
    return

  signatureFilePath = input("Escriba la ruta de la FIRMA a verificar (el documento .sig): ")
  filePath = input("Escriba la ruta del DOCUMENTO original que se ha firmado: ")
  print("Espere por favor, estamos tramitando su petición. Esto puede llevar tiempo")
  res = verifySignature(filePath, signatureFilePath, pubKey)
  if res:
    print("La firma es correcta.")
  elif res == False: 
    print("La firma no es correcta.")
  elif res is None:
    print("No se ha podido verificar la firma")


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
