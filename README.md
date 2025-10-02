# RSA-OAEP Implementation

Projeto para Universidade de Brasília com implementação completa de RSA-OAEP (Optimal Asymmetric Encryption Padding) para criptografia segura de mensagens.

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

### 3. Classe `RSA_OAEP` (RSA-OEAP.py)

Classe integrada que combina RSA com OAEP para criptografia segura:

- **Herança múltipla**: Herda de RSA e OEAP
- **Sincronização automática**: Ajusta tamanhos de chave automaticamente
- **Interface simplificada**: Métodos encrypt/decrypt seguros

**Métodos principais:**
- `generate_keys()`: Gera chaves RSA e configura OAEP
- `encrypt(plaintext)`: Criptografia segura com padding OAEP
- `decrypt(ciphertext)`: Descriptografia segura removendo padding

## Como Executar

### Requisitos
- Python 3.6+
- Biblioteca `hashlib` (padrão)
- Biblioteca `os` (padrão)

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

## Desenvolvimento Futuro

- [ ] Adicionar suporte a assinatura digital
- [ ] Implementar PSS (Probabilistic Signature Scheme)

## Referencias

1. [OAEP - Optimal Asymmetric Encryption Padding](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
2. [MGF1 - Mask Generation Function](https://en.wikipedia.org/wiki/Mask_generation_function)
3. [RSA Cryptosystem](https://en.wikipedia.org/wiki/RSA_cryptosystem)
4. [RFC 3447 - PKCS #1 v2.1](https://tools.ietf.org/html/rfc3447)
5. [Miller-Rabin Primality Test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)

## Licença

Este projeto está licenciado sob os termos especificados no arquivo LICENSE.
