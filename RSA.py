import os

class RSA():
    def __init__(self, bits=2048): 
        self.public_key = None
        self.private_key = None
        self.bits = bits

    def encrypt(self, plaintext):
        if self.public_key is None:
            raise ValueError("Chave pública não definida. Gere as chaves primeiro.")

        m = int.from_bytes(plaintext.encode('utf-8'), byteorder='big')
        e, n = self.public_key
        ciphertext = self.mod_exp(m, e, n)
        return ciphertext

    def decrypt(self, ciphertext):
        if self.private_key is None:
            raise ValueError("Chave privada não definida. Gere as chaves primeiro.")
        
        d, n = self.private_key

        print("Usando chave privada. Isso pode demorar um pouco...")

        m = self.mod_exp(ciphertext, d, n)

        # Converte o inteiro de volta para string
        byte_count = (m.bit_length() + 7) // 8
        m_bytes = m.to_bytes(byte_count, 'big')

        try:
            plaintext = m_bytes.decode('utf-8')
        except UnicodeDecodeError:
            plaintext = "Erro ao decodificar a mensagem."

        return plaintext

    def generate_keys(self):
        p = self._generatePrimes(self.bits // 2)
        q = self._generatePrimes(self.bits // 2)

        print(f"Primo p: {p}")
        print(f"Primo q: {q}")

        n = p * q
        phi = (p - 1) * (q - 1)

        # Choose e, where 1 < e < phi(n) and gcd(e, phi(n)) == 1
        # É um número coprimo a phi(n), os valores 65537, 17 e 3 são comunmente usados
        # Usar o valor 65537 por ser eficiente e seguro
        e = 65537

        # Compute d such that e * d ≡ 1 (mod phi(n)) 
        # Esse cálculo é feito pelo modular multiplicativo inverso e com o algoritmo extendido de Euclides
        d = self._modInverse(e, phi)

        self.public_key = (e, n)
        self.private_key = (d, n)

    def mod_exp(self, base, exp, mod):
        """Calcula (base^exp) mod mod usando exponenciação modular eficiente."""
        # Ignorando caso de m = 1
        result = 1
        base = base % mod
        while exp > 0:
            if (exp % 2) == 1:  # Se exp é ímpar, multiplica a base pelo resultado
                result = (result * base) % mod
            exp = exp >> 1  # Divide exp por 2
            base = (base * base) % mod  # Eleva a base ao quadrado
        return result

    def _generatePrimes(self, bits=1024):
        """Gera um número primo de 'bits' bits usando o teste de Miller-Rabin."""

        while True:
            randomByte = os.urandom(bits // 8)
            num = int.from_bytes(randomByte, byteorder='big')

            mascara_msb = 1 << (bits-1)

            num = num | mascara_msb  # Garantir que o bit mais significativo é 1 (garantir 1024 bits)
            num = num | 1  # Garantir que o número é ímpar (bit menos significativo igual a 1)

            # Testar se é primo usando o teste de Miller-Rabin
            if self._isPrime(num):
                return num

    def _modInverse(self, e, phi):
        """
        Calcula o inverso modular de a mod m usando o algoritmo estendido de Euclides.
        Retorna x tal que (a * x) % m == 1
        Referência: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
        """
        g, x, _ = self._xgcd(e, phi)
        if g != 1:
            raise ValueError('O inverso modular não existe')
        else:
            return x % phi

    def _xgcd(self, a, b):
        """
        Algoritmo estendido de Euclides.
        Referência: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
        """
        x0, x1, y0, y1 = 0, 1, 1, 0
        while a != 0:
            (q, a), b = divmod(b, a), a
            y0, y1 = y1, y0 - q * y1
            x0, x1 = x1, x0 - q * x1
        return b, x0, y0
    
    def _isPrime(self, n, k=40):
        """ Testa se n é um número primo usando o Teste de Miller-Rabin."""
        # Casos triviais
        if n <= 1:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        # 1. Encontrar r e s tais que n - 1 = 2^s * r, com r ímpar
        s = 0
        r = n - 1
        while r % 2 == 0:
            s += 1
            r //= 2

        # 2. Realizar o teste 'k' vezes
        for _ in range(k):
            # Escolher um 'a' aleatório no intervalo [2, n-2]
            # (O 'a' é o "testemunho" do teste)
            a = int.from_bytes(os.urandom(r.bit_length() // 8 + 1), 'big') % (n - 3) + 2
            
            # Calcular x = a^r mod n
            x = pow(a, r, n)

            if x == 1 or x == n - 1:
                continue
            
            # 3. Loop principal para o teste
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                # Se o loop terminar sem x = n - 1, 'n' é composto
                return False
                
        # Se o teste passar 'k' vezes, 'n' é primo com alta probabilidade
        return True

if __name__ == "__main__":
    if __name__ == "__main__":
        rsa = RSA()
        rsa.generate_keys()
        print("Chave Pública: ", rsa.public_key)
        print("Chave Privada: ", rsa.private_key)

        mensagem = "Mensagem de teste para RSA, fé que agora vai meu senhor"
        print("Mensagem Original: ", mensagem)

        ciphertext = rsa.encrypt(mensagem)
        print("Mensagem Criptografada: ", ciphertext)

        decrypted_message = rsa.decrypt(ciphertext)
        print("Mensagem Descriptografada: ", decrypted_message)