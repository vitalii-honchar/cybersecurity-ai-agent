"""
Vulnerable FastAPI Application - FOR TESTING PURPOSES ONLY
This application contains intentional security vulnerabilities for testing AI security agents.
DO NOT use in production or expose to the internet.
"""

from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import sqlite3
import hashlib
import secrets
import os
import subprocess
import base64
from datetime import datetime

# Initialize FastAPI app
app = FastAPI(
    title="Vulnerable Test API",
    description="⚠️ INTENTIONALLY VULNERABLE - For Security Testing Only",
    version="1.0.0"
)

# Security instance for basic auth
security = HTTPBasic()

# In-memory user storage (Vulnerability: No encryption, stored in memory)
users_db = {
    "admin": {
        "password": "admin123",  # Vulnerability: Weak password
        "role": "admin",
        "email": "admin@vulnerable.com",
        "api_key": "secret-admin-key-123"
    },
    "user": {
        "password": "password",  # Vulnerability: Weak password
        "role": "user", 
        "email": "user@vulnerable.com",
        "api_key": "user-api-key-456"
    },
    "test": {
        "password": "test",  # Vulnerability: Extremely weak password
        "role": "guest",
        "email": "test@vulnerable.com",
        "api_key": "test-key-789"
    }
}

# Session storage (Vulnerability: In-memory, no encryption)
active_sessions = {}

# File upload storage
uploaded_files = []

# Pydantic models
class User(BaseModel):
    username: str
    email: str
    role: str

class UserCreate(BaseModel):
    username: str
    password: str
    email: str
    role: Optional[str] = "user"

class LoginRequest(BaseModel):
    username: str
    password: str

class SearchRequest(BaseModel):
    query: str
    filters: Optional[Dict[str, Any]] = {}

class FileUpload(BaseModel):
    filename: str
    content: str  # Base64 encoded

# Root endpoint with information disclosure
# @app.get("/", response_class=HTMLResponse)
# async def root():
#     """Root endpoint - Vulnerability: Information disclosure"""
#     return """
#     <html>
#         <head><title>Vulnerable Test API</title></head>
#         <body>
#             <h1>🔓 Vulnerable Test API</h1>
#             <p><strong>⚠️ WARNING: This is an intentionally vulnerable application for testing purposes!</strong></p>
            
#             <h2>Available Endpoints:</h2>
#             <ul>
#                 <li><a href="/docs">📚 API Documentation (Swagger)</a></li>
#                 <li><a href="/users">👥 List Users</a></li>
#                 <li><a href="/admin/debug">🐛 Debug Info</a></li>
#                 <li><a href="/search?q=test">🔍 Search</a></li>
#                 <li><a href="/files">📁 File Management</a></li>
#             </ul>
            
#             <h2>Test Credentials:</h2>
#             <pre>
# Username: admin    Password: admin123
# Username: user     Password: password
# Username: test     Password: test
#             </pre>
            
#             <h2>Known Vulnerabilities:</h2>
#             <ul>
#                 <li>SQL Injection in search</li>
#                 <li>Weak authentication</li>
#                 <li>Information disclosure</li>
#                 <li>Command injection</li>
#                 <li>Path traversal</li>
#                 <li>Weak passwords</li>
#                 <li>No rate limiting</li>
#                 <li>Insecure direct object references</li>
#             </ul>
#         </body>
#     </html>
#     """

# Vulnerability: Information Disclosure - Lists all users without authentication
@app.get("/users", response_model=List[User])
async def get_users():
    """Get all users - Vulnerability: No authentication required"""
    return [
        User(username=username, email=data["email"], role=data["role"])
        for username, data in users_db.items()
    ]

# Vulnerability: Weak Authentication
@app.post("/login")
async def login(login_data: LoginRequest):
    """Login endpoint - Vulnerability: Weak authentication, information disclosure"""
    username = login_data.username
    password = login_data.password
    
    # Vulnerability: Case-insensitive username check
    for user, data in users_db.items():
        if user.lower() == username.lower() and data["password"] == password:
            # Vulnerability: Predictable session tokens
            session_token = hashlib.md5(f"{username}{datetime.now()}".encode()).hexdigest()
            active_sessions[session_token] = {
                "username": user,
                "role": data["role"],
                "created": datetime.now()
            }
            
            # Vulnerability: Exposing sensitive information
            return {
                "message": "Login successful",
                "session_token": session_token,
                "user_info": {
                    "username": user,
                    "role": data["role"],
                    "email": data["email"],
                    "api_key": data["api_key"]  # Vulnerability: API key exposure
                }
            }
    
    # Vulnerability: Information disclosure in error messages
    if username in users_db:
        raise HTTPException(status_code=401, detail=f"Invalid password for user '{username}'")
    else:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")

# Vulnerability: SQL Injection (simulated)
@app.get("/search")
async def search_users(q: str, role: Optional[str] = None):
    """Search users - Vulnerability: SQL Injection simulation"""
    
    # Simulate SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name LIKE '%{q}%'"
    if role:
        query += f" AND role = '{role}'"
    
    # Vulnerability: Exposing raw SQL query
    results = []
    for username, data in users_db.items():
        if q.lower() in username.lower() or q.lower() in data["email"].lower():
            if not role or data["role"] == role:
                results.append({
                    "username": username,
                    "email": data["email"],
                    "role": data["role"],
                    "sql_query": query  # Vulnerability: SQL query exposure
                })
    
    # Vulnerability: Special handling for SQL injection attempts
    if "'" in q or "OR" in q.upper() or "UNION" in q.upper():
        results.append({
            "message": "Potential SQL injection detected!",
            "query": query,
            "all_users": list(users_db.keys()),  # Vulnerability: Data leakage
            "database_info": "SQLite 3.39.4, users table has columns: id, username, password, email, role"
        })
    
    return {"results": results, "query": query}

# Vulnerability: Command Injection
@app.get("/admin/system")
async def system_info(cmd: Optional[str] = "whoami"):
    """System information - Vulnerability: Command injection"""
    try:
        # Vulnerability: Direct command execution without sanitization
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return {
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr,
            "return_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out", "command": cmd}
    except Exception as e:
        return {"error": str(e), "command": cmd}

# Vulnerability: Path Traversal
@app.get("/files/{file_path:path}")
async def read_file(file_path: str):
    """Read file - Vulnerability: Path traversal"""
    try:
        # Vulnerability: No path sanitization
        with open(file_path, 'r') as f:
            content = f.read()
        return {
            "file_path": file_path,
            "content": content,
            "size": len(content)
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")

# Vulnerability: Insecure Direct Object Reference
@app.get("/user/{user_id}")
async def get_user_by_id(user_id: str):
    """Get user by ID - Vulnerability: No authorization check"""
    # Vulnerability: Direct access to any user data
    if user_id in users_db:
        user_data = users_db[user_id]
        return {
            "username": user_id,
            "password": user_data["password"],  # Vulnerability: Password exposure
            "email": user_data["email"],
            "role": user_data["role"],
            "api_key": user_data["api_key"]
        }
    raise HTTPException(status_code=404, detail="User not found")

# Vulnerability: No input validation
@app.post("/user")
async def create_user(user: UserCreate):
    """Create user - Vulnerability: No input validation, password policy"""
    # Vulnerability: No password strength validation
    # Vulnerability: No duplicate username check
    users_db[user.username] = {
        "password": user.password,  # Vulnerability: Plain text password storage
        "role": user.role,
        "email": user.email,
        "api_key": f"api-key-{len(users_db)}"
    }
    
    return {
        "message": f"User '{user.username}' created successfully",
        "password": user.password,  # Vulnerability: Password in response
        "total_users": len(users_db)
    }

# Vulnerability: Information disclosure in debug endpoint
@app.get("/admin/debug")
async def debug_info():
    """Debug information - Vulnerability: Sensitive information exposure"""
    return {
        "all_users": users_db,  # Vulnerability: All user data with passwords
        "active_sessions": active_sessions,
        "system_info": {
            "python_version": "3.9.0",
            "fastapi_version": "0.104.1",
            "server": "uvicorn",
            "environment": "development"
        },
        "secret_keys": [
            "super-secret-key-123",
            "jwt-secret-456", 
            "database-password-789"
        ],
        "internal_endpoints": [
            "/admin/backup",
            "/admin/logs", 
            "/internal/metrics"
        ]
    }

# Vulnerability: File upload without validation
@app.post("/upload")
async def upload_file(file: FileUpload):
    """Upload file - Vulnerability: No file validation"""
    try:
        # Vulnerability: No file type validation
        content = base64.b64decode(file.content)
        
        uploaded_files.append({
            "filename": file.filename,
            "size": len(content),
            "uploaded_at": datetime.now().isoformat(),
            "content_preview": content[:100].decode('utf-8', errors='ignore')
        })
        
        # Vulnerability: Attempt to execute uploaded files
        if file.filename.endswith('.py'):
            return {
                "message": f"Python file '{file.filename}' uploaded and ready for execution",
                "execute_url": f"/execute/{file.filename}",
                "warning": "File will be executed without sandboxing!"
            }
        
        return {
            "message": f"File '{file.filename}' uploaded successfully",
            "file_id": len(uploaded_files) - 1
        }
    except Exception as e:
        return {"error": f"Upload failed: {str(e)}"}

# Health check endpoint (secure)
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

# Run the application
if __name__ == "__main__":
    import uvicorn
    print("🚨 WARNING: Starting VULNERABLE application for testing purposes only!")
    print("📍 Available at: http://localhost:8000")
    print("📚 API docs at: http://localhost:8000/docs")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")