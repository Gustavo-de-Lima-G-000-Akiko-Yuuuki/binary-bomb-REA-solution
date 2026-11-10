# RE-ALL-THE-THINGS — Análise de Engenharia Reversa e Solução Completa

Documentação técnica da engenharia reversa realizada no binário **`bomb.exe`** (desafio CTF estilo *Binary Bomb* x86), incluindo o diagnóstico do bug de compilação no Estágio 3, a correção implementada em **`bomb_corrigido.exe`** e o gabarito oficial de desarme.

---

## 1. Gabarito Rápido de Desarme

| Estágio | Tipo de Verificação | Entrada Exata (Sem aspas) |
| :--- | :--- | :--- |
| **Estágio 1** | Comparação direta (`strcmp`) | `hunter2` |
| **Estágio 2** | Comparação em array de stack | `Captain Picard` |
| **Estágio 3** | Cifra de César ROT-8 invertida | `hail caesar!` *(requer `bomb_corrigido.exe`)* |
| **Estágio 4** | Decodificação XOR contra tabela | `lolggwp` |
| **Estágio 5** | Equação polinomial FPU x87 ($=9001$) | `79856` |
| **Estágio Secreto** | Polling assíncrono de hardware | Pressionar no teclado: **`6`**, **`5`**, **`4`** |

---

## 2. Detalhamento Técnico Estágio por Estágio

### Estágio 1 (VA `0x004018F5`)
* **Lógica:** O programa aloca o buffer de entrada via `0x40148c` (`fgets` com remoção de `\n`) e chama `0x409388` (`strcmp`) comparando o texto digitado diretamente com o ponteiro em `0x0040bd65`.
* **String no Binário:** `hunter2`
* **Resultado:** `hunter2`

---

### Estágio 2 (VA `0x0040194F`)
* **Lógica:** A função monta uma cadeia de caracteres diretamente na pilha (`stack` do frame local) usando instruções literais de 32 e 16 bits:
  * `movl $0x74706143, -0x23(%ebp)` $\rightarrow$ ASCII `"Capt"`
  * `movl $0x206e6961, -0x1f(%ebp)` $\rightarrow$ ASCII `"ain "`
  * `movl $0x61636950, -0x1b(%ebp)` $\rightarrow$ ASCII `"Pica"`
  * `movw $0x6472, -0x17(%ebp)` $\rightarrow$ ASCII `"rd"`
  * `movb $0x00, -0x15(%ebp)` $\rightarrow$ Terminador nulo `\0`
* Em seguida, percorre um loop `cmp %al, %dl` byte a byte.
* **Resultado:** `Captain Picard`

---

### Estágio 3 (VA `0x004019E8`) — O Bug do Binário Original
* **Lógica Pretendida pelo Autor:** Uma cifra de César clássica (ROT-8). O binário armazena em `0x0040bd97` a string cifrada:
  `piqt(kim{iz)`
  Aplicando a descriptografia padrão com deslocamento reverso ($-8$):
  * `'p' - 8 = 'h'`
  * `'i' - 8 = 'a'`
  * `'q' - 8 = 'i'`
  * `'t' - 8 = 'l'`
  * `'(' - 8 = ' '`
  * `'k' - 8 = 'c'`
  * `'i' - 8 = 'a'`
  * `'m' - 8 = 'e'`
  * `'{' - 8 = 's'`
  * `'i' - 8 = 'a'`
  * `'z' - 8 = 'r'`
  * `')' - 8 = '!'`
  * Frase resultante: **`hail caesar!`**

#### Por que o `bomb.exe` original é impossível de passar pelo teclado?
No código-fonte original em C, o autor cometeu um erro de digitação no operador:
Escreveu `if (target[i] + 8 != input[i])` em vez de `target[i] - 8`.

Ao compilar com GCC para x86 de 32 bits, gerou as seguintes instruções:
```asm
0x401a21: movzx  eax, byte ptr [eax]        ; Carrega target[i]
0x401a24: movsx  eax, al                    ; Extensão de sinal para 32 bits
0x401a27: lea    edx, [eax + 8]             ; edx = target[i] + 8 (SOMA EM VEZ DE SUBTRAIR)
...
0x401a32: movzx  eax, byte ptr [eax]        ; Carrega input[i] digitado
0x401a35: movsx  eax, al                    ; Extensão de sinal: aceita -128 a +127
0x401a38: cmp    edx, eax                   ; Compara esperado vs digitado
0x401a3a: je     0x401a48
0x401a3c: call   0x401507                   ; EXPLODE A BOMBA
```

1. **Incompatibilidade no primeiro caractere:** Como o binário soma `+8`, para o primeiro caractere `'p'` (112) ele calcula `112 + 8 = 120` (`'x'`). Digitar `'h'` (`104`) explode de imediato.
2. **Impossibilidade matemática nos índices 8 e 10:**
   * Índice 8: Caractere `'{'` (ASCII 123) $\rightarrow 123 + 8 =$ **`131`**.
   * Índice 10: Caractere `'z'` (ASCII 122) $\rightarrow 122 + 8 =$ **`130`**.
   Como a instrução `0x401a35` utiliza **`movsx`** (extensão de `signed char`), qualquer valor no byte do teclado com código $\ge 128$ tem o bit de sinal ativado e é convertido para **número negativo** (`131` vira `-125`).
   Como $+131 \neq -125$, **nenhum caractere do teclado no binário sem patch consegue passar deste loop**.

---

### Estágio 4 (VA `0x00401A72`)
* **Lógica:** Decodificação por operação bit a bit XOR ($\oplus$) de 7 bytes.
* **Tabela fixa em `0x0040bdd4`:** `14 c3 60 e3 47 63 d6`
* **Buffer da pilha em `[ebp-0x127]`:** `78 ac 0c 84 20 14 a6`
* **Cálculo:**
  * `0x14 ^ 0x78 = 0x6c` (`'l'`)
  * `0xc3 ^ 0xac = 0x6f` (`'o'`)
  * `0x60 ^ 0x0c = 0x6c` (`'l'`)
  * `0xe3 ^ 0x84 = 0x67` (`'g'`)
  * `0x47 ^ 0x20 = 0x67` (`'g'`)
  * `0x63 ^ 0x14 = 0x77` (`'w'`)
  * `0xd6 ^ 0xa6 = 0x70` (`'p'`)
* **Resultado:** `lolggwp`

---

### Estágio 5 (VA `0x00401B34`)
* **Lógica:** A função lê uma sequência de 5 caracteres numéricos ($d_0, d_1, d_2, d_3, d_4$), subtrai `'0'` (`0x30`) de cada um e calcula a soma exponencial acumulada via FPU x87 (`fildl` / `fldl` / `call 0x402d50` [pow]):
  $$\text{Soma} = d_0^1 + d_1^2 + d_2^3 + d_3^4 + d_4^5$$
* A soma final é comparada contra `0x2329` ($9001$ em decimal, alusão ao meme clássico *"It's over 9000!"*).
* **Solução Única de 5 Dígitos:**
  $$7^1 + 9^2 + 8^3 + 5^4 + 6^5 = 7 + 81 + 512 + 625 + 7776 = 9001$$
* **Resultado:** `79856`

---

### Estágio Secreto (VA `0x00401CAE`)
* **Lógica:** Uma thread em segundo plano criada na inicialização (`0x401800` via `CreateThread`) monitora as teclas globais do sistema via `USER32!GetAsyncKeyState` (`0x40e220`).
* A thread lê a tabela em `0x0040a000` em contagem regressiva para os Virtual-Key Codes:
  * Índice 2: `0x36` $\rightarrow$ Tecla **`6`**
  * Índice 1: `0x35` $\rightarrow$ Tecla **`5`**
  * Índice 0: `0x34` $\rightarrow$ Tecla **`4`**
* Ao digitar a sequência, exibe a mensagem de bônus:
  `Congratulations on beating the secret stage!`

---

## 3. A Correção Implementada em `bomb_corrigido.exe`

Para permitir que o desafio funcione conforme o design original do autor (aceitando `hail caesar!` normalmente pelo teclado), foi aplicado um patch binário cirúrgico de **1 byte**:

* **Endereço Virtual:** `0x00401A27` (Offset no arquivo: `0x0E27`)
* **Instrução Original:** `8d 50 08` $\rightarrow$ `lea edx, [eax + 8]`
* **Instrução Corrigida:** `8d 50 f8` $\rightarrow$ `lea edx, [eax - 8]`
* **Byte alterado:** Offset `0x0E29`: de `0x08` para `0xF8` ($-8$ em complemento de dois).

Com essa correção, a Cifra de César passa a subtrair 8 de `piqt(kim{iz)`, validando perfeitamente a string **`hail caesar!`** sem causar estouro de sinal.

---

## 4. Como Executar

Para rodar a versão corrigida interativamente:

```cmd
cd /d "D:\WENCON\SOFTWARE wecon\PROJETO_MONTADORA_CAIXAS\03_IHM_PI3070IG\tools\TESTE"
bomb_corrigido.exe
```

Digite as senhas uma por linha conforme o gabarito. Ao finalizar a 5ª fase, a mensagem de sucesso será exibida:
```text
You've completed RE-ALL-THE-THINGS!
```

