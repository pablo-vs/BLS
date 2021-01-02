from curve.fields import FQFac

BLS12_381_FQ_MODULUS = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

BLS12_381_FQ2_MODULUS = (1,0,1)

BLS12_381_FQ12_MODULUS = (2, 0, 0, 0, 0, 0, -2, 0, 0, 0, 0, 0,1)

FQ = FQFac(BLS12_381_FQ_MODULUS)
FQ2 = FQ.extend(BLS12_381_FQ2_MODULUS, "u")
FQ12 = FQ.extend(BLS12_381_FQ12_MODULUS, "u")
