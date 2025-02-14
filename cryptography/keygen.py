from sympy import randprime, mod_inverse
from math import log2

def rsa_keygen_with_sympy(key_size):
    print(f"generating RSA key pair with key size {key_size} bits")

    #gen two large primes
    bit_size = key_size // 2
    p = randprime(2**(bit_size - 1), 2**bit_size)  
    q = randprime(2**(bit_size - 1), 2**bit_size)
    while p == q:  
        q = randprime(2**(bit_size - 1), 2**bit_size)

    n = p * q

    #comp eulers
    phi = (p - 1) * (q - 1)

    #choose pub expo e
    e = 65537
    if phi % e == 0:
        raise ValueError("e must be coprime")

    # comp priv expo d
    d = mod_inverse(e, phi)

    #output pub n priv keys
    print(f"public Key: (n={n}, e={e})")
    print(f"private Key: (n={n}, d={d})")

    return (n, e), (n, d)

key_size = 1024
public_key, private_key = rsa_keygen_with_sympy(key_size)

#save keys to files
with open("public_key.txt", "w") as pub_file:
    pub_file.write(f"n={public_key[0]}\ne={public_key[1]}\n")

with open("private_key.txt", "w") as priv_file:
    priv_file.write(f"n={private_key[0]}\nd={private_key[1]}\n")

print("keys saved to 'public_key.txt' and 'private_key.txt'.")