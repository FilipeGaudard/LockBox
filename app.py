from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import sqlite3
import jwt
import datetime
import hashlib
import secrets
import base64

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'lockbox-master-key-2026'
app.config['JSON_AS_ASCII'] = False

# ============= SETUP DO BANCO =============
def init_db():
    conn = sqlite3.connect('lockbox.db')
    conn.execute('PRAGMA encoding = "UTF-8"')
    cursor = conn.cursor()
    
    # Tabela de usuários
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            master_password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabela de credenciais armazenadas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vault_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service_name TEXT NOT NULL,
            website_url TEXT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            notes TEXT,
            category TEXT,
            is_favorite BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Limpar dados existentes (para evitar duplicação)
    cursor.execute('DELETE FROM vault_items')
    cursor.execute('DELETE FROM users')
    
    # Resetar auto-increment
    cursor.execute('DELETE FROM sqlite_sequence WHERE name="users"')
    cursor.execute('DELETE FROM sqlite_sequence WHERE name="vault_items"')
    
    # Usuários de exemplo
    users_data = [
        ('andreia.security', 'andreia@lockbox.com', hashlib.sha256('senha01'.encode()).hexdigest()),
        ('juliana.developer', 'juliana@lockbox.com', hashlib.sha256('senha02'.encode()).hexdigest()),
        ('kevin.admin', 'kevin@lockbox.com', hashlib.sha256('senha03'.encode()).hexdigest()),
    ]
    
    cursor.executemany('INSERT OR IGNORE INTO users (username, email, master_password) VALUES (?, ?, ?)', users_data)
    
    # Credenciais sensíveis de exemplo (base64 para "ofuscar" visualmente)
    vault_items = [
        # andreia - User ID 1
        (1, 'AWS Production Account', 'https://aws.amazon.com', 'andreia@empresa.com', 
         base64.b64encode('AKIAI44QH8DHBEXAMPLE'.encode()).decode(), 
         'Conta de produção - NÃO COMPARTILHAR', 'Cloud', 1),
        
        (1, 'GitHub Enterprise', 'https://github.com/empresa', 'andreia-empresa', 
         base64.b64encode('ghp_xT9kP2mN8qL5wR3vY6zA1bC4dE7fF0gH'.encode()).decode(), 
         'Token com acesso admin aos repos', 'Development', 1),
        
        (1, 'Banco Corporativo', 'https://banco.com.br', 'andreia.silva', 
         base64.b64encode('S3nh@Banc0#2026!'.encode()).decode(), 
         'Conta para pagamentos de fornecedores', 'Finance', 1),
        
        (1, 'Gmail Pessoal', 'https://gmail.com', 'andreia.personal@gmail.com', 
         base64.b64encode('MyP3rs0n@lP@ss'.encode()).decode(), 
         'Email pessoal', 'Personal', 0),
        
        # juliana - User ID 2
        (2, 'Stripe API Keys', 'https://stripe.com', 'juliana@startup.io', 
         base64.b64encode('sk_live_51HxJ8K2eZvKYlo2C9rK3dN0pQ1mL5wX8yT6vZ3aB'.encode()).decode(), 
         'Chaves de produção - CRITICAL', 'Payment', 1),
        
        (2, 'Database Production', 'postgres://db.empresa.com:5432', 'postgres', 
         base64.b64encode('Pr0d_DB_P@ssw0rd_2026'.encode()).decode(), 
         'Master database password', 'Database', 1),
        
        (2, 'LinkedIn Premium', 'https://linkedin.com', 'juliana.developer', 
         base64.b64encode('L1nk3d!n#Pro'.encode()).decode(), 
         'Conta premium para recrutamento', 'Social', 0),
        
        (2, 'OpenAI API', 'https://platform.openai.com', 'juliana@startup.io', 
         base64.b64encode('sk-proj-abcdef123456789ABCDEF'.encode()).decode(), 
         'API key com $5000 de crédito', 'AI', 1),
        
        # kevin - User ID 3
        (3, 'Office 365 Admin', 'https://admin.microsoft.com', 'kevin@empresa.com', 
         base64.b64encode('@dmin_0ff1c3_2026!'.encode()).decode(), 
         'Conta de administrador global', 'Admin', 1),
        
        (3, 'VPN Corporativa', 'vpn.empresa.com', 'kevin.admin', 
         base64.b64encode('VPN_S3cur3_K3y_2026'.encode()).decode(), 
         'Acesso VPN com privilégios elevados', 'Network', 1),
        
        (3, 'Twitter Business', 'https://twitter.com', '@empresa_oficial', 
         base64.b64encode('Tw1tt3r_Bu$1n3ss!'.encode()).decode(), 
         'Conta oficial da empresa - 500k seguidores', 'Social', 1),
    ]
    
    cursor.executemany('''
        INSERT OR IGNORE INTO vault_items 
        (user_id, service_name, website_url, username, password, notes, category, is_favorite) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', vault_items)
    
    conn.commit()
    conn.close()

# ============= HTML FRONTEND =============
HTML_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🔒 LockBox - Password Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #4a4a6a 0%, #6b5b95 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
        }
        .header h1 { 
            font-size: 2.2em; 
            margin-bottom: 8px;
            font-weight: 600;
            letter-spacing: -0.5px;
        }
        .header p { 
            opacity: 0.9; 
            font-size: 1em;
            font-weight: 300;
        }
        .content { padding: 30px; }
        .section {
            background: #f8f9fb;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 25px;
            border: 1px solid #e1e4e8;
        }
        .section h2 { 
            color: #4a4a6a;
            margin-bottom: 20px;
            font-size: 1.3em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        input, select {
            width: 100%;
            padding: 12px 16px;
            margin: 8px 0;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 14px;
            transition: all 0.2s;
            background: white;
        }
        input:focus, select:focus {
            outline: none;
            border-color: #6b5b95;
            box-shadow: 0 0 0 3px rgba(107, 91, 149, 0.1);
        }
        button {
            background: linear-gradient(135deg, #6b5b95 0%, #4a4a6a 100%);
            color: white;
            padding: 12px 28px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 15px;
            font-weight: 500;
            transition: all 0.2s;
        }
        button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(107, 91, 149, 0.3);
        }
        button:active { transform: translateY(0); }
        .vault-item {
            background: white;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 4px solid #6b5b95;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            position: relative;
        }
        .vault-item.critical { border-left-color: #ef4444; }
        .vault-item.favorite { 
            background: #fffbeb; 
            border-left-color: #f59e0b; 
        }
        .vault-item h3 {
            color: #1f2937;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.1em;
            font-weight: 600;
        }
        .vault-item .meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-top: 15px;
        }
        .vault-item .meta-item {
            background: #f9fafb;
            padding: 12px;
            border-radius: 6px;
        }
        .vault-item .meta-item strong { 
            color: #6b5b95; 
            display: block; 
            margin-bottom: 6px;
            font-size: 13px;
            font-weight: 600;
        }
        .vault-item .password-field {
            background: #f3f4f6;
            padding: 12px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            word-break: break-all;
            margin: 12px 0;
            color: #374151;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            margin-left: 8px;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        .badge.favorite { background: #fef3c7; color: #92400e; }
        .badge.critical { background: #fee2e2; color: #991b1b; }
        .badge.cloud { background: #dbeafe; color: #1e40af; }
        .badge.finance { background: #d1fae5; color: #065f46; }
        .badge.development { background: #e0e7ff; color: #3730a3; }
        .badge.payment { background: #fce7f3; color: #831843; }
        .badge.database { background: #e0f2fe; color: #075985; }
        .badge.ai { background: #f3e8ff; color: #6b21a8; }
        .badge.admin { background: #ffe4e6; color: #9f1239; }
        .badge.network { background: #ccfbf1; color: #134e4a; }
        .badge.social { background: #ddd6fe; color: #5b21b6; }
        .badge.personal { background: #e5e7eb; color: #374151; }
        .alert {
            padding: 14px 16px;
            border-radius: 6px;
            margin: 15px 0;
            font-weight: 400;
            font-size: 14px;
        }
        .alert-success { 
            background: #d1fae5; 
            color: #065f46; 
            border: 1px solid #a7f3d0; 
        }
        .alert-danger { 
            background: #fee2e2; 
            color: #991b1b; 
            border: 1px solid #fecaca; 
        }
        .token-display {
            background: #1e293b;
            color: #10b981;
            padding: 16px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            word-break: break-all;
            margin: 12px 0;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            border: 1px solid #e5e7eb;
        }
        .stat-card .number { 
            font-size: 2.5em; 
            color: #6b5b95; 
            font-weight: 700;
        }
        .stat-card .label { 
            color: #6b7280; 
            margin-top: 8px;
            font-size: 13px;
            font-weight: 500;
        }
        .logo {
            font-size: 2.5em;
            margin-bottom: 12px;
        }
        .info-text {
            margin-top: 15px; 
            color: #6b7280; 
            font-size: 13px;
            line-height: 1.6;
        }
        .info-text strong {
            color: #4a4a6a;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🔒</div>
            <h1>LockBox</h1>
            <p>Secure Password Manager</p>
        </div>
        
        <div class="content">
            <!-- LOGIN SECTION -->
            <div class="section">
                <h2>🔑 Login</h2>
                <input type="text" id="username" placeholder="Username" value="andreia.security">
                <input type="password" id="password" placeholder="Master Password" value="senha01">
                <button onclick="login()">Unlock Vault</button>
                <div class="info-text">
                    <strong>Test Accounts:</strong><br>
                    andreia.security / senha01<br>
                    juliana.developer / senha02<br>
                    kevin.admin / senha03
                </div>
                <div id="loginResult"></div>
            </div>
            
            <!-- MY VAULT SECTION -->
            <div class="section">
                <h2>🗄️ My Vault</h2>
                <button onclick="getMyVault()">Load My Passwords</button>
                <div id="myVaultStats"></div>
                <div id="myVault"></div>
            </div>
        </div>
    </div>

    <script>
        let token = '';
        let currentUserId = null;
        
        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            });
            
            const data = await response.json();
            const resultDiv = document.getElementById('loginResult');
            
            if (response.ok) {
                token = data.token;
                currentUserId = data.user_id;
                resultDiv.innerHTML = `
                    <div class="alert alert-success">
                        ✅ <strong>Vault Unlocked Successfully</strong><br>
                        User: ${data.username} (ID: ${data.user_id})<br>
                        Email: ${data.email}
                    </div>
                    <div class="token-display">
                        <strong>JWT Token:</strong><br>${token}
                    </div>
                `;
            } else {
                resultDiv.innerHTML = `<div class="alert alert-danger">❌ ${data.error}</div>`;
            }
        }
        
        async function getMyVault() {
            if (!token) {
                alert('🔒 Please login first');
                return;
            }
            
            const response = await fetch('/api/vault/my-items', {
                headers: {'Authorization': `Bearer ${token}`}
            });
            
            const data = await response.json();
            
            if (response.ok) {
                const statsDiv = document.getElementById('myVaultStats');
                statsDiv.innerHTML = `
                    <div class="stats">
                        <div class="stat-card">
                            <div class="number">${data.items.length}</div>
                            <div class="label">Total Items</div>
                        </div>
                        <div class="stat-card">
                            <div class="number">${data.items.filter(i => i.is_favorite).length}</div>
                            <div class="label">Favorites</div>
                        </div>
                        <div class="stat-card">
                            <div class="number">${new Set(data.items.map(i => i.category)).size}</div>
                            <div class="label">Categories</div>
                        </div>
                    </div>
                `;
                
                const vaultDiv = document.getElementById('myVault');
                vaultDiv.innerHTML = '<h3 style="margin: 20px 0; color: #4a4a6a; font-weight: 600;">Your Stored Credentials</h3>' + 
                    data.items.map(item => renderVaultItem(item)).join('');
            }
        }
        
        function renderVaultItem(item) {
            const decoded = atob(item.password);
            const isCritical = item.notes && (
                item.notes.toLowerCase().includes('critical') || 
                item.notes.toLowerCase().includes('production') ||
                item.notes.toLowerCase().includes('admin')
            );
            
            return `
                <div class="vault-item ${isCritical ? 'critical' : ''} ${item.is_favorite ? 'favorite' : ''}">
                    <h3>
                        ${item.service_name}
                        ${item.is_favorite ? '<span class="badge favorite">⭐ Favorite</span>' : ''}
                        ${isCritical ? '<span class="badge critical">🚨 Critical</span>' : ''}
                        <span class="badge ${item.category.toLowerCase()}">${item.category}</span>
                    </h3>
                    
                    <div class="meta">
                        <div class="meta-item">
                            <strong>🆔 Item ID</strong>
                            ${item.id}
                        </div>
                        <div class="meta-item">
                            <strong>👤 Username</strong>
                            ${item.username}
                        </div>
                        <div class="meta-item">
                            <strong>🌐 Website</strong>
                            <a href="${item.website_url}" target="_blank" style="color: #6b5b95; text-decoration: none;">${item.website_url}</a>
                        </div>
                        <div class="meta-item">
                            <strong>📅 Created</strong>
                            ${new Date(item.created_at).toLocaleDateString('pt-BR')}
                        </div>
                    </div>
                    
                    <div style="margin-top: 15px;">
                        <strong style="color: #4a4a6a; font-size: 14px;">🔑 Password (Decoded)</strong>
                        <div class="password-field">${decoded}</div>
                    </div>
                    
                    ${item.notes ? `
                        <div style="margin-top: 15px;">
                            <strong style="color: #4a4a6a; font-size: 14px;">📝 Notes</strong>
                            <div style="background: #fef3c7; padding: 12px; border-radius: 6px; margin-top: 8px; color: #78350f; font-size: 13px;">
                                ${item.notes}
                            </div>
                        </div>
                    ` : ''}
                </div>
            `;
        }
    </script>
</body>
</html>
'''

# ============= API ROUTES =============

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    conn = sqlite3.connect('lockbox.db')
    conn.text_factory = str
    cursor = conn.cursor()
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute('SELECT id, username, email FROM users WHERE username = ? AND master_password = ?', 
                   (username, password_hash))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    
    token = jwt.encode({
        'user_id': user[0],
        'username': user[1],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        "token": token,
        "user_id": user[0],
        "username": user[1],
        "email": user[2]
    }), 200

@app.route('/api/vault/my-items', methods=['GET'])
def get_my_items():
    """Endpoint CORRETO - Valida ownership"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return jsonify({"error": "Token required"}), 401
    
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
    except:
        return jsonify({"error": "Invalid token"}), 401
    
    conn = sqlite3.connect('lockbox.db')
    conn.text_factory = str
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, service_name, website_url, username, password, notes, 
               category, is_favorite, created_at, last_modified
        FROM vault_items 
        WHERE user_id = ?
        ORDER BY is_favorite DESC, service_name ASC
    ''', (user_id,))
    
    items = cursor.fetchall()
    conn.close()
    
    return jsonify({
        "items": [{
            "id": item[0],
            "service_name": item[1],
            "website_url": item[2],
            "username": item[3],
            "password": item[4],
            "notes": item[5],
            "category": item[6],
            "is_favorite": bool(item[7]),
            "created_at": item[8],
            "last_modified": item[9],
            "user_id": user_id
        } for item in items]
    }), 200

@app.route('/api/vault/items/<int:item_id>', methods=['GET'])
def get_vault_item(item_id):
    """⚠️ ENDPOINT VULNERÁVEL - BOLA CRÍTICO!"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return jsonify({"error": "Token required"}), 401
    
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
    except:
        return jsonify({"error": "Invalid token"}), 401
    
    conn = sqlite3.connect('lockbox.db')
    cursor = conn.cursor()
    
    # 🚨 VULNERABILIDADE CRÍTICA: Não valida se user_id == owner
    cursor.execute('''
        SELECT id, user_id, service_name, website_url, username, password, 
               notes, category, is_favorite, created_at, last_modified
        FROM vault_items 
        WHERE id = ?
    ''', (item_id,))
    
    item = cursor.fetchone()
    conn.close()
    
    if not item:
        return jsonify({"error": "Item not found"}), 404
    
    # Retorna a credencial de QUALQUER usuário! 🔓
    return jsonify({
        "id": item[0],
        "user_id": item[1],
        "service_name": item[2],
        "website_url": item[3],
        "username": item[4],
        "password": item[5],
        "notes": item[6],
        "category": item[7],
        "is_favorite": bool(item[8]),
        "created_at": item[9],
        "last_modified": item[10],
        "current_user_id": user_id
    }), 200

if __name__ == '__main__':
    init_db()
    print("\n" + "="*70)
    print("🔒 LockBox - Password Manager")
    print("="*70)
    print("\n📍 URL: http://localhost:5001")
    print("\n👥 Test Accounts:")
    print("   andreia.security / senha01")
    print("   juliana.developer / senha02")
    print("   kevin.admin / senha03")
    print("\n⚠️  Educational purposes only\n")
    app.run(debug=True, port=5001)
