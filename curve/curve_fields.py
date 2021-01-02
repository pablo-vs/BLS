from .fields import FQFac

#orden del cuerpo finito sobre el que se define la curva
BLS12_381_FQ_MODULUS = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

#polinomios para contruir las extensiones sobre el cuerpo
BLS12_381_FQ2_MODULUS = (1,0,1)
BLS12_381_FQ12_MODULUS = (2, 0, 0, 0, 0, 0, -2, 0, 0, 0, 0, 0,1)

#genera el cuerpo finito con ese modulo
FQ = FQFac(BLS12_381_FQ_MODULUS)

#genera las extensión con esos modulos. u es la representación de la variable de los polinomios ej: u^2 + 1
FQ2 = FQ.extend(BLS12_381_FQ2_MODULUS, "u")
FQ12 = FQ.extend(BLS12_381_FQ12_MODULUS, "u")
