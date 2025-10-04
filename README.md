# RSA-OAEP Implementation

Projeto para Universidade de Brasília com implementação completa de RSA-OAEP (Optimal Asymmetric Encryption Padding) para criptografia segura de mensagens e SHA3 (Secure Hash algorithm 3) para assinatura digital.

## Classes Implementadas

### 1. Classe `RSA` (RSA.py)

Implementação "textbook" do algoritmo RSA, incluindo:

- **Geração de Chaves**: Gera primos seguros usando teste de Miller-Rabin
- **Criptografia**: Operação matemática básica do RSA (`m^e mod n`)
- **Descriptografia**: Operação inversa (`c^d mod n`)
- **Algoritmo Euclidiano Estendido**: Para cálculo do inverso modular

**Métodos principais:**
- `generate_keys(bits=2048)`: Gera par de chaves pública/privada
- `encrypt(plaintext)`: Criptografa string diretamente (inseguro - use RSA_OAEP)
- `decrypt(ciphertext)`: Descriptografa mensagem

⚠️ **Aviso**: A classe RSA sozinha é vulnerável a ataques. Use sempre com padding OAEP.

### 2. Classe `OEAP` (OEAP.py)

Implementação do esquema de preenchimento OAEP conforme RFC 3447:

- **Encoding**: Aplica padding seguro usando SHA-256 e MGF1
- **Decoding**: Remove padding e recupera mensagem original
- **MGF1**: Função de geração de máscara baseada em hash

**Métodos principais:**
- `encode(data, label=b'')`: Aplica padding OAEP aos dados
- `decode(em, label=b'')`: Remove padding e recupera dados originais
- `mgf1(seed, maskLen)`: Função de geração de máscara

### 3. Classe `RSA_OAEP` (RSA_OEAP.py)

Classe integrada que combina RSA com OAEP para criptografia segura:

- **Herança múltipla**: Herda de RSA e OEAP
- **Sincronização automática**: Ajusta tamanhos de chave automaticamente
- **Interface simplificada**: Métodos encrypt/decrypt seguros

**Métodos principais:**
- `generate_keys()`: Gera chaves RSA e configura OAEP
- `encrypt(plaintext)`: Criptografia segura com padding OAEP
- `decrypt(ciphertext)`: Descriptografia segura removendo padding

### 4. Classe `SHA3_256` (SHA_3.py)

Implementação do hash sha256 de acordo com FIPS PUB 202:

- **Ajuste de padding**: Ajusta o tamanho da mensagem para o tamanho do bloco
- **Constantes de deslocamento e rounds**: Utiliza matriz de números triangulares

**Métodos principais:**
- `get_hash()`: Retorna em bytes o hash com 64 caracteres UTF-8
- `_absorb(block)`: Recebe um bloco de no máximo 135 caracteres UTF-8
- `_permute()`: Realiza os 24 hounds com as manipulações de matriz

## Como Executar

### Requisitos
- Python 3.6+
- Biblioteca `hashlib` (padrão)
- Biblioteca `os` (padrão)
- Biblioteca `struct` (padrão)

### Execução Rápida

Execute o arquivo principal para ver uma demonstração:

```bash
python3 RSA-OEAP.py
```

### Uso Programático

#### Exemplo Básico

```python
from RSA_OEAP import RSA_OAEP

# 1. Criar instância da classe
rsa_cipher = RSA_OAEP(bits=2048)

# 2. Gerar par de chaves
rsa_cipher.generate_keys()

# 3. Criptografar mensagem
message = "Sua mensagem secreta aqui"
ciphertext = rsa_cipher.encrypt(message)
print(f"Texto cifrado: {ciphertext}")

# 4. Descriptografar mensagem
decrypted = rsa_cipher.decrypt(ciphertext)
print(f"Texto original: {decrypted}")
```

## Parâmetros de Configuração

### Tamanhos de Chave Recomendados

- **1024 bits**: Mínimo para testes (não recomendado para produção)
- **2048 bits**: Padrão atual, adequado para a maioria dos casos
- **3072 bits**: Recomendado para dados sensíveis
- **4096 bits**: Máxima segurança (mais lento)

### Considerações de Performance

| Tamanho da Chave | Geração | Criptografia | Descriptografia |
|------------------|---------|--------------|-----------------|
| 1024 bits        | ~0.1s   | ~0.001s      | ~0.01s         |
| 2048 bits        | ~0.5s   | ~0.001s      | ~0.05s         |
| 4096 bits        | ~5s     | ~0.002s      | ~0.2s          |

## Segurança

### Características de Segurança
- ✅ **Padding OAEP**: Previne ataques de texto cifrado escolhido
- ✅ **Primos Seguros**: Geração usando teste de Miller-Rabin
- ✅ **SHA-256**: Hash criptográfico forte
- ✅ **MGF1**: Função de máscara padronizada
- ✅ **Entropia Forte**: Usa `os.urandom()` para aleatoriedade

### Limitações Conhecidas
- ⚠️ **Tamanho da Mensagem**: Limitado pelo tamanho da chave
- ⚠️ **Performance**: Descriptografia pode ser lenta com chaves grandes
- ⚠️ **Side-Channel**: Não protegido contra ataques de canal lateral

## Estrutura Técnica

### Fluxo de Criptografia
```
Mensagem → UTF-8 → OAEP Encoding → RSA Encryption → Ciphertext 
```

### Fluxo de Descriptografia
```
Ciphertext → RSA Decryption → OAEP Decoding → UTF-8 → Mensagem
```

### Execução Rápida Para SHA256

Execute o arquivo principal para ver uma demonstração:

```bash
python3 SHA_3.py
```

### Uso Programático

#### Exemplo Básico

```python
from RSA_OEAP import RSA_OAEP

# Texto de exemplo
msg = "Mensagem de teste para RSA com OAEP com SHA-3"

# Cria uma instância do SHA3 e obtem o hash único de acordo com a mensagem
sha3 = SHA3_256()
hash = sha3.get_hash(msg)
print("SHA3-256:", hash)

# Junte o hash com a mensagem com um caractere que permite separar depois
msg_hash = msg + "|" + hash

# Enviada a mensagem; Do lado do receptor separa a mensagem do hash
msg_part, hash_part = decrypted_message.split("|", 1)

# Obetenha o hash do texto recebido
sha3_new = SHA3_256()
hash_new = sha3_new.get_hash(msg_part)
print("SHA3-256 calculado:", hash_new)
print("SHA3-256 recebido:", hash_part)

# Compare se o hash calculado é igual ao recebido
if hash_part == hash_new:
    print("Mensagem recebida está integra")
```

## Estrutura Técnica

### Fluxo de Hashing
```
Mensagem → UTF-8 → Padding →  Absorve → Permuta → Formatação → Hash
```

## Fluxo completo
```
Cripto: Mensagem → UTF-8 → OAEP Encoding → RSA Encryption → Ciphertext 
Hash: Mensagem → UTF-8 → Padding →  Absorve → Permuta → Formatação → Hash
Assinatura Digital (sender): Mensagem → Cripto(Mensagem+Hash) → Base64
Assinatura Digital (receive): Base64 → Descripto → Mensagem+Hash → VerificarHash 
Base64 → Ciphertext → RSA Decryption → OAEP Decoding → UTF-8 → Mensagem
```

## Desenvolvimento Futuro

- [ ] Adicionar suporte a assinatura digital
- [ ] Implementar PSS (Probabilistic Signature Scheme)

## Referencias

1. [OAEP - Optimal Asymmetric Encryption Padding](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
2. [MGF1 - Mask Generation Function](https://en.wikipedia.org/wiki/Mask_generation_function)
3. [RSA Cryptosystem](https://en.wikipedia.org/wiki/RSA_cryptosystem)
4. [RFC 3447 - PKCS #1 v2.1](https://tools.ietf.org/html/rfc3447)
5. [Miller-Rabin Primality Test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)
6. []
## Licença

Este projeto está licenciado sob os termos especificados no arquivo LICENSE.



