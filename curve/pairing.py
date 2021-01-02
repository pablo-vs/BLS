from curve.curve import Point, CurvePoint, G1, curve_order
from curve.curve_fields import FQ, FQ2, FQ12, BLS12_381_FQ_MODULUS as field_modulus


ate_loop_count = 15132376222941642752
log_ate_loop_count = 62



def linefunc(P1: CurvePoint, P2: CurvePoint, Q: Point) -> FQ:
    if P1.is_infinite() or P2.is_infinite() or Q.is_infinite():
        raise ValueError("Can't compute line function on infinite point")

    x1, y1 = P1
    x2, y2 = P2
    xq, yq = Q

    if x1 != x2:
        m = (y2 - y1) / (x2 - x1)
        return m * (xq - x1) - (yq - y1)
    elif y1 == y2:
        m = 3 * x1**2 / (2 * y1)
        return m * (xq - x1) - (yq - y1)
    else:
        return xq - x1


def embed_FQ12(P: Point) -> Point:
    x, y = P
    return type(P)(FQ12(x), FQ12(y))

"""
# Check consistency of the "line function"
one, two, three = G1, 2*G1, 3*G1
negone, negtwo, negthree = (
    G1*(curve_order - 1),
    G1*(curve_order - 2),
    G1*(curve_order - 3),
)


assert linefunc(one, two, one) == 0
assert linefunc(one, two, two) == 0
assert linefunc(one, two, three) != 0
assert linefunc(one, two, negthree) == 0
assert linefunc(one, negone, one) == 0
assert linefunc(one, negone, negone) == 0
assert linefunc(one, negone, two) != 0
assert linefunc(one, one, one) == 0
assert linefunc(one, one, two) != 0
assert linefunc(one, one, negtwo) == 0
"""

def miller_loop(P: CurvePoint, Q: CurvePoint) -> FQ12:
    if P.is_infinite() or Q.is_infinite():
        return FQ12.one()

    R = Q
    f = FQ12.one()
    for i in range(log_ate_loop_count, -1, -1):
        f = f * f * linefunc(R, R, P)
        R = 2*R
        if ate_loop_count & (2**i):
            f = f * linefunc(R, Q, P)
            R = R + Q

    #assert R == multiply(Q, ate_loop_count)
    #Q1 = (Q[0] ** field_modulus, Q[1] ** field_modulus)
    #assert is_on_curve(Q1, b12)
    #nQ2 = (Q1[0] ** field_modulus, -Q1[1] ** field_modulus)
    #assert is_on_curve(nQ2, b12)
    #f = f * linefunc(R, Q1, P)
    #R = add(R, Q1)
    #f = f * linefunc(R, nQ2, P)
    #R = add(R, nQ2) This line is in many specifications but it technically does nothing
    return f ** ((field_modulus ** 12 - 1) // curve_order)

    
def pairing(P: CurvePoint, Q: CurvePoint) -> FQ12:
    return miller_loop(embed_FQ12(P), Q.twist())
