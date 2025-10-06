from OEAP import OEAP
from RSA import RSA


class RSA_OAEP(RSA, OEAP):
    def __init__(self, bits=2048):
        RSA.__init__(self, bits)
        OEAP.__init__(self, bits)

    def generate_keys(self):
        super().generate_keys()
        # Alinha o tamanho da chave do OAEP com o tamanho efetivo do módulo RSA
        modulus_bits = self.public_key[1].bit_length()
        modulus_bytes = (modulus_bits + 7) // 8
        self.key_size = modulus_bytes * 8

    def encrypt(self, plaintext: str):
        if self.public_key is None:
            raise ValueError("Chave pública não definida. Gere as chaves primeiro.")

        # Codifica a mensagem usando OAEP
        encoded_message = self.encode(plaintext.encode('utf-8'))

        print("Mensagem codificada com OAEP:", encoded_message)

        # Converte a mensagem codificada para um inteiro
        m = int.from_bytes(encoded_message, byteorder='big')
        e, n = self.public_key

        # Encripta o inteiro usando RSA
        ciphertext = self.mod_exp(m, e, n)
        return ciphertext

    def decrypt(self, ciphertext):
        if self.private_key is None:
            raise ValueError("Chave privada não definida. Gere as chaves primeiro.")

        d, n = self.private_key

        # Decripta o inteiro usando RSA
        m = self.mod_exp(ciphertext, d, n)

        print("Mensagem decriptada com RSA (antes de OAEP):", m)

        # Converte o inteiro de volta para bytes usando o tamanho completo da chave
        key_size_bytes = (self.key_size + 7) // 8
        m_bytes = m.to_bytes(key_size_bytes, 'big')

        # Decodifica a mensagem usando OAEP
        try:
            plaintext_bytes = self.decode(m_bytes)
            plaintext = plaintext_bytes.decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            plaintext = "Erro ao decodificar a mensagem."

        return plaintext
    

if __name__ == "__main__":
    rsa_oeap = RSA_OAEP(bits=2048)
    rsa_oeap.generate_keys()
    message = "Mensagem de teste para RSA com OAEP"
    print("Mensagem Original:", message)
    ciphertext = rsa_oeap.encrypt(message)
    print("Ciphertext:", ciphertext)

    decrypted_message = rsa_oeap.decrypt(ciphertext)
    print("Mensagem Decriptada:", decrypted_message)


