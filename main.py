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


storagePubKeyFile = r"allPublicKeys.txt"

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
    return base64.b64encode(x.val.to_bytes(48, byteorder='little')
            + y.val.to_bytes(48, byteorder='little'))

def decodePubKey(pkStr):
    byte = base64.b64decode(pkStr)
    x = FQ(int.from_bytes(byte[:48], byteorder='little'))
    y = FQ(int.from_bytes(byte[48:], byteorder='little'))
    return BaseCurve(x,y)

def encodePrivKey(sk):
    return base64.b64encode(sk.to_bytes(32, byteorder='little'))

def decodePrivKey(skStr):
    return int.from_bytes(base64.b64decode(skStr), byteorder='little')

def encodeSig(sig):
    x, y = sig
    x0, x1 = x.val[0].val, x.val[1].val
    y0, y1 = y.val[0].val, y.val[1].val
    return base64.b64encode(x0.to_bytes(48, byteorder='little')
            + x1.to_bytes(48, byteorder='little')
            + y0.to_bytes(48, byteorder='little')
            + y1.to_bytes(48, byteorder='little'))

def decodeSig(sigStr):
    byte = base64.b64decode(sigStr)
    x0 = int.from_bytes(byte[:48], byteorder='little')
    x1 = int.from_bytes(byte[48:96], byteorder='little')
    y0 = int.from_bytes(byte[96:144], byteorder='little')
    y1 = int.from_bytes(byte[144:], byteorder='little')
    x = FQ2([x0, x1])
    y = FQ2([y0, y1])
    return ExtCurve(x,y)


def hashToPoint(message):
    # TODO secure hashing function
    hint = int.from_bytes(sha256(message).digest(), byteorder='little')
    h = hint % curve_order
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

  with open(storagePubKeyFile, "a+") as f:
      f.write(name)
      f.write(' ')
      f.write(encodePubKey(pk).decode("utf-8"))
      f.write('\n')

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

  #print(signature)
  #print(H)
  #print(pubKey)
  p1 = pairing(pubKey, H)
  p2 = pairing(G1, signature)
  #print(p1)
  #print(p2)
  return p1 == p2


def auxKeyGenerator():
    name = input("Escriba su nombre: ")
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
  print(" a. Si es usuario del sistema, escriba su nombre.")
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

  signatureFilePath = input("Escriba la ruta de la firma a verificar: ")
  filePath = input("Escriba la ruta del documento firmado: ")

  if verifySignature(filePath, signatureFilePath, pubKey):
    print("La firma es correcta.")
  else: 
    print("La firma no es correcta.")


def main():
  print("Bienvenido al trabajo de CTC sobre curvas elípticas BLS. Se puede: ")
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



"""

BLS12_381_FQ2(x=1106624301960789946748158909871646598348904190322609219168378608841911
898492216282408390352467793829034273514879159u + 1649077438388732385859817655088667066
245504782517249547359861252662675631490090511138983125185251955676080881775131, y=3110
81991676779127471721509924076726996932356427740459944270153530893013507119419478228535
0976196626206342470238723u + 126782964418323818073621591837174637495231035899753538620
0927214907051033380472497364373776011207985516687964055162)
BLS12_381_FQ2(x=3463031491276111053437551085715438993401815136204614267126783225805721
208029984986011411886489382368275818805965886u + 2247212123674941974215108907514019192
503264191178610072130191523851478075383835910648860198776893009435174021599307, y=5460
25818131574661406183621952818227207105997402797858208313381207764114675151023623791919
540747917636939971076970u + 1757145574596997458599070055464714925152652800747649673165
91478496834057574687082396559401291262307359029450538477)
BLS12_381_FQ(x=50532783350983116249148232828292763881353770160137954180130858136804971
1085959338414568906374117041523196126495913, y=984810398263711076044249951760876454249
073578842065543413124405779036630624916572541688343954209521432468067795003)


-7141337075487289341
"""
