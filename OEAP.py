import hashlib
import math
import os

class OEAP():
    # Necessários:
    # Hash function - SHA-256 (recomendado mínimo)
    # Mask generation function - MGF1 (padrão)
    # Label - vazio (padrão)
    # Tamanho do bloco n - tamanho da chave RSA em bytes

    """
    Implementação do esquema de padding OAEP (Optimal Asymmetric Encryption Padding)
    Encode:
    1. Hash the label L using the chosen hash function: lHash = Hash(L)
    2. Generate a padding string PS consisting of (k - mLen - 2 * hLen - 2) bytes with the value 0x00.
    3. Concatenate lHash, PS, the single byte 0x01, and the message M to form a data block DB: DB = lHash || PS || 0x01 || M.  This data block has length k - hLen - 1 bytes.
    4. Generate a random seed of length hLen bytes.
    5. Use the mask generating function to generate a mask of the appropriate length for the data block: dbMask = MGF(seed, k - hLen - 1)
    6 Mask the data block with the generated mask: maskedDB = DB XOR dbMask
    7. Use the mask generating function to generate a mask of length hLen bytes for the seed: seedMask = MGF(maskedDB, hLen)
    8. Mask the seed with the generated mask: maskedSeed = seed XOR seedMask
    9. The encoded (padded) message is the byte 0x00 concatenated with maskedSeed and maskedDB: EM = 0x00 || maskedSeed || maskedDB

    Decode:
    1. Hash the label L using the chosen hash function: lHash = Hash(L)
    2. Split the encoded message EM into its components: EM = 0x00 || maskedSeed || maskedDB (reverse step 9)
    3. Generate the seed mask: seedMask = MGF(maskedDB, hLen)
    4. Recover the seed: seed = maskedSeed XOR seedMask (reverse step 8)
    5. Generate the dbMask: dbMask = MGF(seed, k - hLen - 1)
    6. Recover the data block: DB = maskedDB XOR dbMask (reverse step 6)
    7. Split DB into its components: DB = lHash' || PS || 0x01 || M
        7.1 Verify that lHash' matches lHash. If not, output "decoding" and stop.
        7.2 Scan PS for the first occurrence of the byte 0x01.
        7.3 Verify all bytes of PS are 0x00. If not, output "decoding" and stop.
        7.4 The first byte after PS is 0x01, and the remaining bytes are the message M.
    """

    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.hash_function = hashlib.sha256


    def encode(self, data, label=b''):
        #Verificação do tamanho da mensagem
        k = self.key_size // 8  # Tamanho da chave em bytes
        mLen = len(data)
        hLen = self.hash_function().digest_size
        if mLen > k - 2 * hLen - 2:
            raise ValueError("Mensagem muito longa para o tamanho da chave")
        
        # 1: Hash da label
        lHash = self.hash_function(label).digest()  # Label vazia

        # 2: Geração do padding
        ps = b'\x00' * (k - mLen - 2 * hLen - 2)
        db = lHash + ps + b'\x01' + data

        # 3: Concatenação para formar o bloco de dados
        # db = lHash || PS || 0x01 || M
        db = lHash + ps + b'\x01' + data

        # 4: Geração do seed aleatório
        seed = os.urandom(hLen)

        # 5: Geração do dbMask
        dbMask = self.mgf1(seed, k - hLen - 1)

        # 6: XOR entre db e dbMask
        maskedDB = bytes(x ^ y for x, y in zip(db, dbMask))

        # 7: Geração do seedMask
        seedMask = self.mgf1(maskedDB, hLen)

        # 8: XOR entre seed e seedMask
        maskedSeed = bytes(x ^ y for x, y in zip(seed, seedMask))

        # 9: Construção do bloco codificado
        em = b'\x00' + maskedSeed + maskedDB
        return em
    
    def decode(self, em, label=b''):
        hLen = self.hash_function().digest_size
        k = self.key_size // 8

        # Verificação do tamanho do bloco codificado
        # if len(em) != k or k < 2 * hLen + 2:
        #     raise ValueError("Decoding error")
        
        # 1: Hash da label
        lHash = self.hash_function(label).digest()

        # 2: Separação do bloco codificado
        if em[0] != 0x00:
            raise ValueError("Decoding error")
        maskedSeed = em[1:hLen + 1]
        maskedDB = em[hLen + 1:]

        # 3: Geração do seedMask
        seedMask = self.mgf1(maskedDB, hLen)

        # 4: Recuperação do seed
        seed = bytes(x ^ y for x, y in zip(maskedSeed, seedMask))

        # 5: Geração do dbMask
        dbMask = self.mgf1(seed, k - hLen - 1)

        # 6: Recuperação do bloco de dados
        db = bytes(x ^ y for x, y in zip(maskedDB, dbMask))

        # 7: Separação do bloco de dados
        lHash_prime = db[:hLen]
        if lHash_prime != lHash:
            raise ValueError("Decoding error")
        
        # Encontrar o byte 0x01
        for i in range(hLen, len(db)):
            if db[i] == 0x01:
                message_start = i + 1
                break
            elif db[i] != 0x00:
                raise ValueError("Decoding error")

        return db[message_start:] # Mensagem
    
    def mgf1(self, seed, maskLen):
        """Mask Generation Function based on a hash function (SHA-256)
        
        1. If maskLen > 2^32 * hLen, output "mask too long" and stop.
        2. Let T be the empty octet string.
        3. For counter from 0 to ceil(maskLen / hLen) - 1 do the following:
           A. Convert counter to an octet string C of length 4 with the most significant octet first (I2OSP).
           B. Concatenate the hash of the seed Z and C to the octet string T: T = T || Hash(Z || C).
        4. Output the leading maskLen octets of T as the mask.
        
        """
        hLen = self.hash_function().digest_size
        if maskLen > (2**32) * hLen:
            raise ValueError("mask too long")
        
        T = b''
        for counter in range(0, math.ceil(maskLen / hLen)):  # Ceiling division
            C = counter.to_bytes(4, byteorder='big')
            T += self.hash_function(seed + C).digest()

        return T[:maskLen]
    

if __name__ == "__main__":
    oeap = OEAP(key_size=2048)
    message = b'Hello, World!'
    print("Original message:", message)

    encoded = oeap.encode(data=message)
    print("Encoded message:", encoded)

    decoded = oeap.decode(em=encoded)
    print("Decoded message:", decoded)

    assert message == decoded, "Decoded message does not match the original"