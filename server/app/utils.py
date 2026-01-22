from umbral import pre, keys

def reencrypt(ciphertext_capsule, rk: keys.PublicKey):

    capsule, ciphertext = ciphertext_capsule
    
    cfrag = pre.reencrypt(kfrag=rk, capsule=capsule)
    capsule.attach_cfrag(cfrag)
   
    return ciphertext
