#!/bin/bash

# Local Wordlist Installer for FFUF
# Downloads essential wordlists to local repository folder

set -e

echo "🔍 Installing essential wordlists for FFUF directory discovery..."

# Create wordlists directory in repository
WORDLIST_DIR="wordlists"
mkdir -p "$WORDLIST_DIR"
cd "$WORDLIST_DIR"

echo "📁 Created wordlists directory: $(pwd)"

# 1. Download SecLists (Essential - Most comprehensive)
echo "📥 Downloading SecLists (The gold standard)..."
if [ ! -d "SecLists" ]; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git
    echo "✅ SecLists downloaded"
else
    echo "⚠️ SecLists already exists, updating..."
    cd SecLists && git pull && cd ..
fi

# 2. Download specific high-quality wordlists
echo "📥 Downloading additional specialized wordlists..."

# Create directories for organized wordlists
mkdir -p {directories,files,parameters,subdomains,api,admin}

# 2.1 Assetnote Wordlists (High quality, updated monthly)
echo "🎯 Downloading Assetnote wordlists..."
wget -q --show-progress -O "directories/assetnote-httparchive-directories.txt" \
    "https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2024_03_28.txt" || echo "⚠️ Assetnote directories failed"

wget -q --show-progress -O "files/assetnote-httparchive-php.txt" \
    "https://wordlists-cdn.assetnote.io/data/automated/httparchive_php_2024_03_28.txt" || echo "⚠️ Assetnote PHP files failed"

# 2.2 OneListForAll (Comprehensive modern wordlist)
echo "🚀 Downloading OneListForAll..."
wget -q --show-progress -O "directories/onelistforall.txt" \
    "https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt" || echo "⚠️ OneListForAll failed"

# 2.3 RAFT wordlists (High quality, commonly recommended)
echo "📋 Downloading RAFT wordlists..."
wget -q --show-progress -O "directories/raft-medium-directories.txt" \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" || echo "⚠️ RAFT medium failed"

wget -q --show-progress -O "directories/raft-large-directories.txt" \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt" || echo "⚠️ RAFT large failed"

# 2.4 API-specific wordlists
echo "🔌 Downloading API wordlists..."
wget -q --show-progress -O "api/api-endpoints.txt" \
    "https://raw.githubusercontent.com/hAPI-hacker/Hacking-APIs/main/wordlists/api_endpoints.txt" || echo "⚠️ API endpoints failed"

# 2.5 Common web files and parameters
echo "🗂️ Downloading web files and parameters..."
wget -q --show-progress -O "parameters/burp-parameter-names.txt" \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt" || echo "⚠️ Parameters failed"

# 3. Create custom optimized wordlists for development
echo "📝 Creating custom optimized wordlists..."

# 3.1 Quick scan wordlist (for fast testing)
cat >"directories/quick-scan.txt" <<'EOF'
admin
api
backup
config
dashboard
debug
dev
docs
login
panel
test
uploads
users
wp-admin
.env
.git
robots.txt
sitemap.xml
swagger.json
openapi.json
graphql
EOF

# 3.2 Web application focused wordlist
cat >"directories/webapp-focused.txt" <<'EOF'
admin
admin/
api
api/
api/v1
api/v2
api/docs
backup
backups
config
config.php
config.json
dashboard
debug
dev
development
docs
documentation
download
downloads
files
images
login
logout
panel
private
staging
static
test
testing
uploads
upload
user
users
wp-admin
wp-content
wp-includes
.env
.git
.htaccess
config
robots.txt
sitemap.xml
swagger.json
swagger-ui
openapi.json
graphql
health
status
metrics
EOF

# 3.3 Vulnerability-focused wordlist
cat >"directories/vuln-focused.txt" <<'EOF'
admin
admin.php
admin/debug
admin/config
admin/logs
admin/backup
api
api/debug
api/v1
backup
backup.sql
config
config.php
config.bak
debug
debug.php
phpinfo.php
info.php
test.php
robots.txt
.env
.env.backup
.git
.svn
sitemap.xml
crossdomain.xml
web.config
.htaccess
server-status
server-info
EOF

# 3.4 File extension wordlist for common web files
cat >"files/common-extensions.txt" <<'EOF'
php
html
htm
js
css
json
xml
txt
log
bak
backup
old
conf
config
sql
zip
tar
gz
rar
pdf
doc
docx
xls
xlsx
EOF

# 4. Create symlinks for easy access to most common lists
echo "🔗 Creating convenient symlinks..."
ln -sf "SecLists/Discovery/Web-Content/common.txt" "common.txt" 2>/dev/null || true
ln -sf "SecLists/Discovery/Web-Content/directory-list-2.3-small.txt" "small.txt" 2>/dev/null || true
ln -sf "SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt" "medium.txt" 2>/dev/null || true
ln -sf "SecLists/Discovery/Web-Content/directory-list-2.3-big.txt" "big.txt" 2>/dev/null || true

# 5. Create wordlist configuration file for tools
echo "🔧 Creating wordlist configuration..."
cat >"wordlist-config.txt" <<EOF
# FFUF Wordlist Configuration
# Generated: $(date)

# Quick testing (30 entries - 30 seconds)
QUICK="$(pwd)/directories/quick-scan.txt"

# Web app focused (50 entries - 1 minute) 
WEBAPP="$(pwd)/directories/webapp-focused.txt"

# Vulnerability focused (40 entries - 1 minute)
VULN="$(pwd)/directories/vuln-focused.txt"

# Standard wordlists
COMMON="$(pwd)/common.txt"
SMALL="$(pwd)/small.txt"
MEDIUM="$(pwd)/medium.txt"
BIG="$(pwd)/big.txt"

# High-quality modern wordlists
ONELISTFORALL="$(pwd)/directories/onelistforall.txt"
RAFT_MEDIUM="$(pwd)/directories/raft-medium-directories.txt"
RAFT_LARGE="$(pwd)/directories/raft-large-directories.txt"

# Assetnote (updated monthly)
ASSETNOTE_DIRS="$(pwd)/directories/assetnote-httparchive-directories.txt"
ASSETNOTE_PHP="$(pwd)/files/assetnote-httparchive-php.txt"

# API specific
API_ENDPOINTS="$(pwd)/api/api-endpoints.txt"

# Parameters and files
PARAMETERS="$(pwd)/parameters/burp-parameter-names.txt"
EXTENSIONS="$(pwd)/files/common-extensions.txt"

# SecLists paths
SECLISTS_ROOT="$(pwd)/SecLists"
SECLISTS_WEB="$(pwd)/SecLists/Discovery/Web-Content"
SECLISTS_API="$(pwd)/SecLists/Discovery/Web-Content/api"
EOF

# 6. Create test script
echo "🧪 Creating test script..."
cat >"test-wordlists.sh" <<'EOF'
#!/bin/bash
# Test script for wordlists

echo "🧪 Testing wordlists with example target..."

TARGET="http://localhost:8000"

echo "1. Quick scan (30 entries):"
ffuf -w directories/quick-scan.txt -u "$TARGET/FUZZ" -mc 200,404 -t 10 -timeout 5 -s

echo -e "\n2. Common directories:"
ffuf -w common.txt -u "$TARGET/FUZZ" -mc 200,404 -t 10 -timeout 5 -s | head -5

echo -e "\n3. File extensions:"
ffuf -w directories/quick-scan.txt -u "$TARGET/FUZZ" -e .php,.html,.js -mc 200,404 -t 10 -timeout 5 -s

echo -e "\n✅ Wordlist testing complete!"
EOF

chmod +x "test-wordlists.sh"

# 7. Display summary
echo ""
echo "🎉 Wordlist installation complete!"
echo "📊 Downloaded wordlists summary:"
echo "   📁 Directory: $(pwd)"
echo "   📋 SecLists: $(find SecLists -name "*.txt" 2>/dev/null | wc -l) wordlist files"
echo "   🚀 Custom lists: $(find directories files -name "*.txt" | wc -l) custom wordlists"

echo ""
echo "📖 Available wordlists:"
echo "   🏃 Quick scan: $(wc -l <directories/quick-scan.txt) entries (30 seconds)"
echo "   🌐 Web app: $(wc -l <directories/webapp-focused.txt) entries (1 minute)"
echo "   🔍 Vuln focused: $(wc -l <directories/vuln-focused.txt) entries (1 minute)"
if [ -f "common.txt" ]; then
    echo "   📝 Common: $(wc -l <common.txt) entries (2-3 minutes)"
fi

echo ""
echo "🔧 Usage examples:"
echo "   # Quick test"
echo "   ffuf -w wordlists/directories/quick-scan.txt -u http://localhost:8000/FUZZ -mc 200,403,401"
echo ""
echo "   # Web app focused"
echo "   ffuf -w wordlists/directories/webapp-focused.txt -u http://localhost:8000/FUZZ -mc 200,403,401"
echo ""
echo "   # With file extensions"
echo "   ffuf -w wordlists/directories/webapp-focused.txt -u http://localhost:8000/FUZZ -e .php,.html,.js"
echo ""
echo "   # Test installation"
echo "   cd wordlists && ./test-wordlists.sh"

echo ""
echo "📄 View configuration: cat wordlists/wordlist-config.txt"
echo "🧪 Test wordlists: cd wordlists && ./test-wordlists.sh"
