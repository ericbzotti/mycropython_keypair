import os
import ubinascii

# Paramètres de la courbe Ed25519
p = 2**255 - 19
d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
B_x = 15112221349535400772501151409588531511454012693041857206046113283949847762202
B_y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
B = (B_x, B_y)

def inv(x):
    """Inverse modulo p"""
    return pow(x, p - 2, p)

def point_add(P, Q):
    """Addition de deux points sur la courbe Ed25519 (formules en coordonnées affines)"""
    (x1, y1) = P
    (x2, y2) = Q
    denom_x = (1 + d * x1 * x2 * y1 * y2) % p
    denom_y = (1 - d * x1 * x2 * y1 * y2) % p
    x3 = ((x1 * y2 + y1 * x2) * inv(denom_x)) % p
    y3 = ((y1 * y2 - x1 * x2) * inv(denom_y)) % p
    return (x3, y3)

def scalar_mult(s, P):
    """Multiplication scalaire par méthode double et addition avec affichage de progression"""
    Q = None
    R = P
    step = 0
    while s > 0:
        if s & 1:
            Q = R if Q is None else point_add(Q, R)
        s //= 2
        R = point_add(R, R)
        step += 1
        print("Progression - étape", step, R)
    return Q

def encode_point(P):
    """
    Encodage d'un point en forme compressée (32 octets) comme pour Ed25519.
    On encode la coordonnée y en little-endian et on intègre le bit de parité de x dans l'octet de poids fort.
    """
    (x, y) = P
    y_bytes = y.to_bytes(32, 'little')
    if x & 1:
        y_bytes = bytearray(y_bytes)
        y_bytes[31] |= 0x80  # Fixer le bit de parité de x
        y_bytes = bytes(y_bytes)
    return y_bytes

def _generate_keypair():
    print("Génération de la clé privée...")
    sk = bytearray(os.urandom(32))
    print("Clé privée brute (Hex):", sk.hex())
    
    print("Application du clamping sur la clé privée...")
    sk[0] &= 248
    sk[31] &= 127
    sk[31] |= 64
    print("Clé privée après clamping (Hex):", sk.hex())
    
    a = int.from_bytes(sk, 'little')
    print("Conversion en entier terminée, valeur a =", a)
    
    print("Calcul de la clé publique par multiplication scalaire...")
    A = scalar_mult(a, B)
    print("Clé publique calculée.")
    
    A_bytes = encode_point(A)
    print("Encodage de la clé publique terminé.")
    
    return bytes(sk), A_bytes

def encode_base58(data):
    """Encodage simple en Base58"""
    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    encoded = ''
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = BASE58_ALPHABET[rem] + encoded
    return encoded

def generate_keypair():
    print("Début de la génération de la paire de clés Ed25519...")
    private_key, public_key = _generate_keypair()
    print("Paire de clés générée.")
    print("Clé privée (Hex):", private_key.hex())
    print("Clé publique (Hex):", public_key.hex())

    print("Encodage de la clé publique en Base58 pour obtenir l'adresse Solana...")
    address = encode_base58(public_key)
    print("Adresse Solana (Base58):", address)

    return private_key, public_key
  
generate_keypair();
