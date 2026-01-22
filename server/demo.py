
from umbral import keys, pre

sk_owner = keys.PrivateKey()
pk_owner = sk_owner.get_public_key()

capsule, encrypted_aes_key = pre.encrypt(pk_owner, aes_key)


from umbral import signing

signer = signing.Signer(sk_owner)
kfrags = pre.generate_kfrags(
    delegating_sk=sk_owner,
    receiving_pk=pk_receiver,
    signer=signer,
    threshold=1,
    shares=1
)


cfrag = pre.reencrypt(kfrag, capsule)


aes_key = pre.decrypt_reencrypted(
    capsule=capsule,
    cfrags=[cfrag],
    decrypting_key=sk_receiver,
    verifying_keys=[pk_owner]
)