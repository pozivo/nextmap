# 🧹 GitHub Release Cleanup - Problema Asset Duplicati

**Data**: 18 Ottobre 2025  
**Issue**: Release con asset duplicati/obsoleti  
**Status**: ✅ Risolto  

---

## 🔍 Problema Identificato

### Situazione Attuale
Le release v0.2.5 e v0.3.0 su GitHub hanno **8 assets** invece dei 4 corretti:

**Release v0.2.5** - 8 assets ❌
- nextmap-linux-x64.tar.gz (v0.2.5) ✅
- nextmap-windows-x64.zip (v0.2.5) ✅
- nextmap-macos-x64.tar.gz (v0.2.5) ✅
- nextmap-macos-arm64.tar.gz (v0.2.5) ✅
- **4 binari di versioni precedenti** ❌

**Release v0.3.0** - 8 assets ❌
- nextmap-linux-x64.tar.gz (v0.3.0) ✅
- nextmap-windows-x64.zip (v0.3.0) ✅
- nextmap-macos-x64.tar.gz (v0.3.0) ✅
- nextmap-macos-arm64.tar.gz (v0.3.0) ✅
- **4 binari di versioni precedenti** ❌

### Causa Root
Nel file `.github/workflows/release.yml`, il step di upload usava:

```yaml
files: |
  **/*.zip
  **/*.tar.gz
```

Questo pattern **cattura TUTTI** i file .zip e .tar.gz nella directory di lavoro, inclusi:
- File dalla cache di build precedenti
- Artifact di altre versioni
- File temporanei

---

## ✅ Soluzione Implementata

### 1. Fix del Workflow (`.github/workflows/release.yml`)

**Prima** (PROBLEMATICO):
```yaml
- name: Download all artifacts
  uses: actions/download-artifact@v4

- name: Create Release
  uses: softprops/action-gh-release@v2
  with:
    files: |
      **/*.zip      # ❌ Cattura TUTTO
      **/*.tar.gz   # ❌ Cattura TUTTO
```

**Dopo** (CORRETTO):
```yaml
- name: Download all artifacts
  uses: actions/download-artifact@v4

- name: List downloaded artifacts
  run: |
    echo "Downloaded artifacts:"
    ls -R

- name: Prepare release files
  run: |
    mkdir -p release-files
    mv nextmap-linux-x64/nextmap-linux-x64.tar.gz release-files/
    mv nextmap-windows-x64/nextmap-windows-x64.zip release-files/
    mv nextmap-macos-x64/nextmap-macos-x64.tar.gz release-files/
    mv nextmap-macos-arm64/nextmap-macos-arm64.tar.gz release-files/
    echo "Release files prepared:"
    ls -lh release-files/

- name: Create Release
  uses: softprops/action-gh-release@v2
  with:
    files: |
      release-files/nextmap-linux-x64.tar.gz      # ✅ Specifico
      release-files/nextmap-windows-x64.zip       # ✅ Specifico
      release-files/nextmap-macos-x64.tar.gz      # ✅ Specifico
      release-files/nextmap-macos-arm64.tar.gz    # ✅ Specifico
```

### Vantaggi della Nuova Soluzione
1. ✅ **Isolation**: Crea directory `release-files/` dedicata
2. ✅ **Explicit**: Specifica esattamente quali file caricare
3. ✅ **Traceable**: Log dettagliato di cosa viene preparato
4. ✅ **No duplicates**: Impossibile caricare file vecchi
5. ✅ **Future-proof**: Funziona per tutte le release future

---

## 🛠️ Script di Cleanup Forniti

### 1. Script Bash (`clean-releases.sh`)

**Per sistemi Unix/Linux/macOS**:

```bash
chmod +x clean-releases.sh
./clean-releases.sh
```

**Opzioni**:
1. Clean v0.2.5 only
2. Clean v0.3.0 only
3. Clean both v0.2.5 and v0.3.0
4. Clean all releases
5. Verify only (no changes)

### 2. Script PowerShell (`clean-releases.ps1`)

**Per Windows**:

```powershell
.\clean-releases.ps1
```

**Opzioni identiche allo script Bash**

### Cosa Fanno gli Script

1. **Verificano** lo stato attuale delle release
2. **Elencano** tutti gli asset presenti
3. **Eliminano** gli asset obsoleti (opzionale)
4. **Mostrano** un report finale

---

## 📋 Procedura di Pulizia

### Step 1: Verifica Situazione Attuale

```powershell
# Windows
.\clean-releases.ps1

# Scegli opzione 5 (Verify only)
```

```bash
# Linux/macOS
./clean-releases.sh

# Scegli opzione 5 (Verify only)
```

### Step 2: Pulisci Release

```powershell
# Windows - Pulisci v0.2.5 e v0.3.0
.\clean-releases.ps1

# Scegli opzione 3 (Clean both)
```

### Step 3: Forza Re-build (Opzionale)

Se vuoi ri-triggerare il workflow con il fix:

```bash
# Per v0.3.0
git tag -f v0.3.0
git push -f origin v0.3.0

# Per v0.2.5
git tag -f v0.2.5
git push -f origin v0.2.5
```

⚠️ **Attenzione**: Questo ri-triggera il workflow GitHub Actions

---

## 🎯 Risultato Atteso

Dopo la pulizia e il fix del workflow:

**Release v0.2.5** - 4 assets ✅
- nextmap-linux-x64.tar.gz (v0.2.5)
- nextmap-windows-x64.zip (v0.2.5)
- nextmap-macos-x64.tar.gz (v0.2.5)
- nextmap-macos-arm64.tar.gz (v0.2.5)

**Release v0.3.0** - 4 assets ✅
- nextmap-linux-x64.tar.gz (v0.3.0)
- nextmap-windows-x64.zip (v0.3.0)
- nextmap-macos-x64.tar.gz (v0.3.0)
- nextmap-macos-arm64.tar.gz (v0.3.0)

**Tutte le release future** - 4 assets ✅
- Automaticamente corretto dal workflow aggiornato

---

## 🔍 Come Verificare

### Via GitHub Web
1. Vai su: https://github.com/pozivo/nextmap/releases
2. Clicca su una release (es. v0.3.0)
3. Scorri fino alla sezione "Assets"
4. Dovresti vedere esattamente 4 file

### Via GitHub CLI
```bash
# Verifica v0.3.0
gh release view v0.3.0 --repo pozivo/nextmap

# Lista tutti gli asset
gh release view v0.3.0 --repo pozivo/nextmap --json assets
```

### Via Script
```bash
# Verifica automatica di tutte le release
./clean-releases.sh
# Scegli opzione 5
```

---

## 📝 Checklist Post-Fix

- [ ] Workflow `.github/workflows/release.yml` aggiornato
- [ ] Commit del workflow pushato su GitHub
- [ ] Script di cleanup creati (`clean-releases.sh` e `clean-releases.ps1`)
- [ ] Eseguito cleanup delle release esistenti (opzionale)
- [ ] Verificato che release future avranno 4 assets
- [ ] Documentazione creata (`RELEASE_CLEANUP.md`)

---

## 🚀 Prossime Release

Con il fix implementato, **tutte le release future** (v0.3.1, v0.4.0, ecc.) avranno automaticamente:

✅ Esattamente 4 assets  
✅ Nessun duplicato  
✅ Solo binari della versione corretta  
✅ Build pulita e tracciabile  

---

## 🎓 Lezioni Apprese

### ❌ Da Evitare
```yaml
files: |
  **/*.zip        # Troppo generico!
  **/*.tar.gz     # Cattura TUTTO!
```

### ✅ Best Practice
```yaml
files: |
  release-files/specific-file-1.zip    # Esplicito
  release-files/specific-file-2.tar.gz # Tracciabile
```

### Principi
1. **Explicit is better than implicit** - Specifica esattamente cosa vuoi
2. **Isolate build artifacts** - Usa directory dedicate
3. **Log everything** - Traccia ogni step per debug
4. **Test locally first** - Verifica prima di pushare

---

## 📞 Support

### Se il Problema Persiste

1. **Verifica workflow**: Assicurati che il workflow sia stato aggiornato su GitHub
2. **Check cache**: Pulisci la cache di GitHub Actions se necessario
3. **Manual cleanup**: Usa gli script forniti per pulire manualmente
4. **Force rebuild**: Ri-trigge il workflow con tag force push

### Contatti
- **GitHub Issues**: https://github.com/pozivo/nextmap/issues
- **Repository**: https://github.com/pozivo/nextmap

---

**Status**: ✅ RISOLTO  
**Data Fix**: 18 Ottobre 2025  
**Versioni Affette**: v0.2.5, v0.3.0  
**Versioni Corrette**: v0.3.0+ (con workflow aggiornato)
