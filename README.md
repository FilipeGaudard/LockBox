# 🔒 LockBox - BOLA/IDOR Vulnerability Lab

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Framework-Flask-green?style=flat-square&logo=flask)
![OWASP](https://img.shields.io/badge/OWASP-API1:2023-red?style=flat-square)

**LockBox** é um laboratório de cibersegurança prático. Trata-se de um Gerenciador de Senhas desenvolvido intencionalmente com uma vulnerabilidade crítica de **Broken Object Level Authorization (BOLA)**, permitindo demonstrar ataques, impacto e, o mais importante, a correção segura do código.

---

## Estrutura do Projeto

Este repositório está dividido em três componentes principais para estudo:

| Arquivo | Função | Descrição |
|:---:|:---:|---|
| **`app.py`** |  O Alvo (Vulnerável) | Aplicação web contendo a falha de autorização BOLA/IDOR no endpoint de recuperação de senhas. |
| **`poc.py`** |  O Ataque (Exploit) | Script Python (Proof of Concept) que automatiza a exploração da falha, extraindo senhas de outros usuários. |
| **`app_secure.py`** |  A Solução (Seguro) | Versão corrigida da aplicação, implementando validação estrita de propriedade do recurso. |

---

## Contexto Técnico

| Categoria | Referência |
|---|---|
| **Vulnerabilidade** | **BOLA (Broken Object Level Authorization)** / IDOR |
| **OWASP API Top 10** | **API1:2023** |
| **CWE** | **CWE-639** (Authorization Bypass Through User-Controlled Key) |
| **Impacto** | Vazamento de dados sensíveis (Confidencialidade) |

---

## Como Executar o Lab

### 1. Instalação
Certifique-se de ter o Python instalado e instale as dependências:
```
pip install -r requirements.txt
```
### 2. Cenário A: Demonstrando a Vulnerabilidade
Neste cenário, agimos como um atacante explorando a falha.

Inicie a aplicação vulnerável:
```
python app.py
```
(O servidor iniciará em http://localhost:5001)

Em outro terminal, execute a Prova de Conceito (PoC):
```
python poc.py
```
Resultado: O script conseguirá acessar o ID 10 (que pertence a outro usuário) e exibirá a senha vazada no terminal.

### 3. Cenário B: Validando a Correção (Remediação)
Neste cenário, agimos como o Engenheiro de Segurança que corrigiu o código.

Pare o servidor anterior (CTRL+C) e inicie a versão segura:
```
python app_secure.py
```
Execute novamente o ataque:
```
python poc.py
```
Resultado: O ataque falhará. O servidor retornará 404 Not Found (ou 403 Forbidden), provando que a validação de propriedade está funcionando.

## Análise do Código
A diferença entre o código vulnerável e o seguro reside na query SQL e na validação de propriedade.

### Código Vulnerável (app.py)
O backend confia cegamente no id enviado pelo usuário, sem verificar se ele é o dono do recurso.
```
# Falha: Recupera o item baseando-se APENAS no ID fornecido na URL
cursor.execute('SELECT * FROM vault_items WHERE id = ?', (item_id,))
```
### Código Seguro (app_secure.py)
Implementamos uma verificação que vincula o id do objeto ao user_id do token de autenticação (JWT).
```
# Correção: O item só é retornado se o ID bater E o user_id for o do solicitante
cursor.execute('''
    SELECT * FROM vault_items 
    WHERE id = ? AND user_id = ?
''', (item_id, current_user_id))
```
# Disclaimer
Este software foi criado para fins estritamente educacionais e de demonstração profissional. Não utilize este código em produção.
