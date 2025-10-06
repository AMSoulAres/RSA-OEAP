# SHA-3 (Keccak) simplificado em Python
# Para fins educacionais, versão didática
import struct
import base64
import random
import string
from RSA_OEAP import RSA_OAEP

class SHA3_256():
    def __init__(self, rate = 1088):

        # Contantes de deslocamento (Rho)
        self.RHO_OFFSETS = [
            [0, 36, 3, 41, 18],
            [1, 44, 10, 45, 2],
            [62, 6, 43, 15, 61],
            [28, 55, 25, 21, 56],
            [27, 20, 39, 8, 14]
        ]

        # Constantes de round (iota)
        self.ROUND_CONSTANTS = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
            0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        ]
        self.rate = rate  # bits para SHA3-256
        self.b = 1600
        self.capacity = self.b - self.rate # c = b - r = 512
        self.lane_size = 64     # 64 = w = 2^l
        self.state = [[0]*5 for _ in range(5)]  # 5x5 matriz de palavras
        self.block_size = self.rate // 8    # 136 quantidade de letras por bloco usando UTF-8
        self.buffer = b""

    def _pad(self, message):
        """Padding simples Keccak"""
        pad_len = self.block_size - (len(message) % self.block_size) # Quanto falta para preencher o bloco
        return message + b'\x80' + b'\x00'*(pad_len-2) + b'\x01'     # Completando o bloco

    def _rotate(self, value, shift):
        return ((value << shift) | (value >> (64 - shift))) & 0xFFFFFFFFFFFFFFFF

    def _permute(self):
        for rnd in range(24):   # 12 + 2*l  l = 6
            # Theta
            C = [self.state[x][0] ^ self.state[x][1] ^ self.state[x][2] ^ self.state[x][3] ^ self.state[x][4] for x in range(5)]
            D = [C[(x-1)%5] ^ self._rotate(C[(x+1)%5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    self.state[x][y] ^= D[x]

            # Rho + Pi
            new_state = [[0]*5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    new_x, new_y = y, (2*x + 3*y) % 5
                    new_state[new_x][new_y] = self._rotate(self.state[x][y], self.RHO_OFFSETS[x][y])
            self.state = new_state

            # Chi
            for y in range(5):
                row = [self.state[x][y] for x in range(5)]
                for x in range(5):
                    self.state[x][y] ^= (~row[(x+1)%5]) & row[(x+2)%5]

            # Iota
            self.state[0][0] ^= self.ROUND_CONSTANTS[rnd]

    def _absorb(self, block):
        # absorve bloco de r bits (r/64 lanes)
        num_lanes = self.rate // self.lane_size # 1088 // 64 = 17
        for i in range(num_lanes):
            start = i*8
            chunk = block[start:start+8].ljust(8, b'\x00')  # Chunk de 64 bits
            lane_value = struct.unpack('<Q', chunk)[0]
            x = i % 5
            y = i // 5 % 5
            self.state[x][y] ^= lane_value                  # Divide o bloco em chunks e espalha na matriz


    def get_hash(self, message: str):
        """Atualiza o estado com a mensagem"""
        self.buffer = message.encode('utf-8')
        padded = self._pad(self.buffer)
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i+self.block_size]
            self._absorb(block)
            self._permute()
        hash_hex = self.digest().hex()
        return hash_hex

    def digest(self):
        """Retorna o hash como bytes"""
        output = []
        for row in self.state:
            for val in row:
                output.extend(struct.pack("<Q", val))
        return bytes(output[:32])  # SHA3-256 → 32 bytes


def mutate_random_char(s: str) -> str:
    s=str(s)
    if not s:
        return s
    i = random.randrange(len(str(s)))
    # escolhe uma letra diferente da atual
    new_char = random.choice([c for c in string.ascii_letters if c != s[i]])
    return s[:i] + new_char + s[i+1:]

# Exemplo de uso
if __name__ == "__main__":
    rsa_oeap = RSA_OAEP(bits=2048)
    rsa_oeap.generate_keys()

    msg = "Mensagem de teste para RSA com OAEP com SHA-3"
    sha3 = SHA3_256()
    hash = sha3.get_hash(msg)
    print("SHA3-256:", hash)
    msg_hash = msg + "|" + hash

    print("Mensagem Original com hash:", msg_hash)
    ciphertext = rsa_oeap.encrypt(msg_hash)
    cipher_bytes = ciphertext.to_bytes((ciphertext.bit_length() + 7) // 8, 'big')
    cipherbase64 = base64.b64encode(cipher_bytes).decode('utf-8')
    # Com alteração no caminho
    cipher_alt = mutate_random_char(ciphertext)
    cipher_bytes_alt = ciphertext.to_bytes((ciphertext.bit_length() + 7) // 8, 'big')
    cipherbase64alt = base64.b64encode(cipher_bytes_alt).decode('utf-8')
    """ ^^^ Bob"""

    print("Ciphertext na base64:", cipherbase64)
    print("Ciphertext com alteração e base64:", cipherbase64alt)  # Trudy

    #
    #try:
    #    decrypted_message = rsa_oeap.decrypt(cipher_alt)    # Da erro poor ter sido alterado
    #except:
    #    print("Erro ao decriptar mensagem com alteração")

    """ ↓↓↓ Alice """
    #Voltando de base64 para int
    ciphertext_new = base64.b64decode(cipherbase64)
    decoded_int = int.from_bytes(ciphertext_new, 'big')
    # Decriptando a mensagem
    decrypted_message = rsa_oeap.decrypt(decoded_int)
    print("Mensagem Decriptada:", decrypted_message)    
    # Confere se está correto
    msg_part, hash_part = decrypted_message.split("|", 1)
    sha3_new = SHA3_256()
    hash_new = sha3_new.get_hash(msg_part)
    print("SHA3-256 calculado:", hash_new)
    print("SHA3-256 recebido:", hash_part)
    if hash_part == hash_new:
        print("Mensagem recebida está integra")

