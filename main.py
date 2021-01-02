storagePubKeyFile = r"C:\Users\Andrea\Desktop\CurvasElipticasBLS\...\allPublicKeys.txt"

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
####TODO    

def keyGenerator(name):
  print("Pablo")
  return (True, "pubKeyPath", "privKeyPath")

def signFile():
  return (True, "signatureFilePath")

def verifySignature(filePath, signatureFilePath, pubKey):
  return True
####TODO
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

  fo = open(privKeyPath, "r")
  privKey = fo.read()
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
      fo = open(storagePubKeyFile, "r")
      for line in fo:
        line = line.split()
        if line[0] == name:
          pubKey = line[1]
          break
      
    else:
      print("Su usuario no existe.")
      return
  
  elif opt == "b":
    fo = open(pubKeyPath, "r")
    pubKey = fo.read()
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
  
    while (opt!= 1 | opt!=2 | opt!=3 | opt!=4):
      if(opt == 4):
        return 0
      print("Escoja una opción válida:")
      opt = menuText()
  
    if opt == 1: #Crear firmas
      auxKeyGenerator()
    elif opt == 2: #Firmar doc
      auxSignFile()
    else: #check firma
      auxVerifySignature()
