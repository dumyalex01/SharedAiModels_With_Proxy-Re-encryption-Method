import random
from umbral import (
    SecretKey, Signer, CapsuleFrag,
    encrypt, generate_kfrags, reencrypt, decrypt_original, decrypt_reencrypted)


alices_secret_key = SecretKey.random()
alices_public_key = alices_secret_key.public_key()

alices_signing_key = SecretKey.random()
alices_verifying_key = alices_signing_key.public_key()
alices_signer = Signer(alices_signing_key)

plaintext = b'Proxy Re-encryption is cool!'
capsule, ciphertext = encrypt(alices_public_key, plaintext)

bobs_secret_key = SecretKey.random()
bobs_public_key = bobs_secret_key.public_key()

bob_capsule = capsule
kfrags = generate_kfrags(delegating_sk=alices_secret_key,
                         receiving_pk=bobs_public_key,
                         signer=alices_signer,
                         threshold=1,
                         shares=1)
cfrags = list() 
for kfrag in kfrags:
    cfrag = reencrypt(capsule=capsule, kfrag=kfrag)
    cfrags.append(cfrag)


bob_cleartext = decrypt_reencrypted(receiving_sk=bobs_secret_key,
                                    delegating_pk=alices_public_key,
                                    capsule=bob_capsule,
                                    verified_cfrags=cfrags,
                                    ciphertext=ciphertext)
print(bob_cleartext)
assert bob_cleartext == plaintext