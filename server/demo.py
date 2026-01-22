from tinyec import registry
import secrets

curve = registry.get_curve("secp256r1")

sk_A = secrets.randbelow(curve.field.n)
pk_A = sk_A * curve.g

sk_B = secrets.randbelow(curve.field.n) 
pk_B = sk_B * curve.g

rk_A_to_B = sk_A.inverse() * pk_B

print("Re-encryption key A→B:", rk_A_to_B)