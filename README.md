# LockBox - Laboratório de Vulnerabilidade BOLA

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Framework-Flask-green?style=flat-square&logo=flask)
![Vulnerability](https://img.shields.io/badge/Vulnerability-BOLA%20%2F%20IDOR-red?style=flat-square)

**LockBox** é uma aplicação de gerenciamento de senhas leve, desenvolvida intencionalmente com uma falha crítica de segurança: **Broken Object Level Authorization (BOLA)**, também conhecida como Insecure Direct Object Reference (IDOR).

Este projeto serve como uma Prova de Conceito (PoC) educacional, demonstrando como falhas de autorização em APIs ocorrem e, principalmente, como corrigi-las de forma segura utilizando Python e Flask.

---

## Contexto Técnico e Frameworks

Este laboratório foca nas seguintes classificações de segurança:

| Framework | ID | Descrição |
|-----------|----|-------------|
| **OWASP API Top 10** | **API1:2023** | **Broken Object Level Authorization (BOLA)**. APIs tendem a expor endpoints que lidam com identificadores de objetos, criando uma grande superfície de ataque se o controle de acesso ao objeto não for validado. |
| **CWE** | **CWE-639** | *Authorization Bypass Through User-Controlled Key*. Ocorre quando o sistema utiliza uma chave controlada pelo usuário para acessar dados sem verificar a permissão. |
| **MITRE ATT&CK** | **T1595** | *Active Scanning*. O ato de sondar endpoints de API para identificar respostas inesperadas ou acesso a dados não autorizados. |
| **MITRE ATT&CK** | **TA0006** | *Credential Access*. A tática final do ataque, resultando no roubo de credenciais via manipulação da API. |

---

## ⚙️ Instalação e Execução

### Pré-requisitos
* Python 3.8+
* pip

### Quick Start
1. Clone o repositório:
   ```
   git clone [https://github.com/FilipeGaudard/LockBox.git](https://github.com/FilipeGaudard/LockBox.git)
   cd LockBox
   ```

2. Instale as dependências:
```
pip install -r requirements.txt
```

3. Execute a aplicação:
```
python app.py
```
O servidor iniciará em http://localhost:5001
