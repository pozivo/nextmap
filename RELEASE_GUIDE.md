# NextMap Release Guide

## Preparazione per il rilascio su GitHub

### 1. **Setup iniziale del repository**

```bash
# Inizializza git (se non già fatto)
git init

# Aggiungi tutti i file
git add .

# Primo commit
git commit -m "🚀 Initial release of NextMap network scanner

- TCP and UDP port scanning
- OS fingerprinting and service detection  
- Multiple output formats (human, JSON, YAML, XML, CSV, Markdown)
- Rate limiting and timing templates
- Progress bars and colored output
- Multi-platform binary distribution"

# Crea repository su GitHub e aggiungi origin
git remote add origin https://github.com/YOUR_USERNAME/nextmap.git

# Push del codice
git push -u origin main
```

### 2. **Test di build locale (opzionale)**

Prima di creare il release, puoi testare la compilazione:

```bash
# Su Linux/macOS
chmod +x build-releases.sh
./build-releases.sh

# Su Windows  
build-releases.bat
```

### 3. **Creazione del primo release**

```bash
# Crea e push del tag per triggerare GitHub Actions
git tag -a v0.1.0 -m "🎉 NextMap v0.1.0

Features:
- Multi-protocol scanning (TCP/UDP)
- OS fingerprinting
- Service detection and vulnerability analysis
- 6 output formats support
- Rate limiting with timing templates
- Cross-platform binaries (Windows, Linux, macOS)"

git push origin v0.1.0
```

### 4. **Verifica del release automatico**

Dopo il push del tag:

1. Vai su GitHub → Actions per vedere il workflow in corso
2. Il build richiederà ~5-10 minuti
3. Se tutto va bene, troverai il release in GitHub → Releases
4. Gli asset includeranno:
   - `nextmap-linux-x64.tar.gz`
   - `nextmap-linux-musl-x64.tar.gz`  
   - `nextmap-windows-x64.zip`
   - `nextmap-macos-x64.tar.gz`
   - `nextmap-macos-arm64.tar.gz`

### 5. **Installazione per gli utenti**

Gli utenti potranno scaricare il binary per la loro piattaforma:

#### Linux/macOS:
```bash
# Download
wget https://github.com/YOUR_USERNAME/nextmap/releases/latest/download/nextmap-linux-x64.tar.gz

# Extract
tar -xzf nextmap-linux-x64.tar.gz

# Run
./nextmap --help
```

#### Windows:
1. Scarica `nextmap-windows-x64.zip` dalla pagina releases
2. Estrai l'archivio  
3. Esegui `nextmap.exe` dal prompt dei comandi

### 6. **Pubblicazione su crates.io (opzionale)**

Se vuoi pubblicare anche su crates.io per `cargo install`:

```bash
# Login (una volta sola)
cargo login YOUR_API_TOKEN

# Publish
cargo publish
```

### 7. **Release successivi**

Per rilasci futuri:

```bash
# Aggiorna versione in Cargo.toml
# Commit delle modifiche
git add .
git commit -m "🔄 Update to v0.2.0"

# Nuovo tag
git tag -a v0.2.0 -m "Release v0.2.0 - Added new features"
git push origin v0.2.0
```

## Troubleshooting

### Build fallisce su GitHub Actions
- Controlla i log in Actions tab
- Verifica che tutte le dipendenze siano specificate in Cargo.toml
- Per errori di cross-compilation, controlla la compatibilità delle librerie

### Tag già esistente
```bash
# Rimuovi tag locale e remoto
git tag -d v0.1.0
git push origin :refs/tags/v0.1.0

# Ricrea il tag
git tag -a v0.1.0 -m "New message"
git push origin v0.1.0
```

### Aggiornare asset del release
- Elimina il release da GitHub
- Elimina il tag
- Ricrea tag e push per triggherare nuovo build

## Monitoraggio

- **GitHub Actions**: Workflow status e logs
- **GitHub Releases**: Download statistics  
- **Issues/PR**: Feedback della community
- **Security**: Dependabot alerts per vulnerabilità

## Best Practices

1. **Semantic Versioning**: Usa vX.Y.Z (major.minor.patch)
2. **Release Notes**: Documenta sempre le modifiche
3. **Testing**: Testa su piattaforme diverse prima del release
4. **Security**: Mantieni dipendenze aggiornate
5. **Documentation**: Aggiorna README per nuove features