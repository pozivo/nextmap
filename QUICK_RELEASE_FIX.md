# 🚀 Guida Rapida - Pulizia Release GitHub

**Data**: 18 Ottobre 2025  
**Problema**: Release con 8 assets invece di 4  
**Status**: ✅ Fix implementato nel workflow  

---

## 📊 Situazione Attuale

### Release v0.2.5 e v0.3.0
Entrambe le release hanno **8 assets** invece di 4:
- 4 binari corretti (versione corretta)
- 4 binari obsoleti (versioni precedenti)

### Workflow Fix
✅ Il workflow è stato corretto nel commit `40b5539`  
✅ Tutte le **release future** avranno automaticamente 4 assets corretti  
✅ Le release esistenti possono essere pulite manualmente  

---

## ⚡ Soluzione Rapida (Senza GitHub CLI)

### Opzione 1: Pulizia Manuale via Web 🌐

1. **Vai su GitHub**:
   - https://github.com/pozivo/nextmap/releases

2. **Per v0.2.5**:
   - Clicca su "v0.2.5"
   - Nella sezione "Assets", clicca sui 3 puntini accanto a ogni asset OBSOLETO
   - Seleziona "Delete"
   - Conferma l'eliminazione

3. **Per v0.3.0**:
   - Ripeti lo stesso processo

4. **Verifica**:
   - Ogni release dovrebbe avere esattamente 4 assets:
     - nextmap-linux-x64.tar.gz
     - nextmap-windows-x64.zip
     - nextmap-macos-x64.tar.gz
     - nextmap-macos-arm64.tar.gz

### Opzione 2: Ri-trigger Workflow (Consigliato) 🔄

Lascia che il workflow aggiornato ricrei la release:

```powershell
# Per v0.3.0 (ultima versione)
git tag -d v0.3.0
git push origin :refs/tags/v0.3.0
git tag v0.3.0
git push origin v0.3.0
```

Questo:
1. ✅ Elimina il tag locale
2. ✅ Elimina il tag su GitHub
3. ✅ Ricrea il tag
4. ✅ Pusha il tag (trigge il workflow)
5. ✅ Il workflow aggiornato caricherà solo 4 assets corretti

**⚠️ Nota**: La release esistente verrà sostituita

---

## 🛠️ Opzione 3: Con GitHub CLI (Opzionale)

### Installazione GitHub CLI

```powershell
# Windows (con winget)
winget install --id GitHub.cli

# Oppure con Chocolatey
choco install gh

# Oppure scarica da: https://cli.github.com/
```

### Dopo l'Installazione

```powershell
# Login
gh auth login

# Verifica release
.\clean-releases.ps1
# Scegli opzione 5 (Verify)

# Pulisci release
.\clean-releases.ps1
# Scegli opzione 3 (Clean both v0.2.5 and v0.3.0)
```

---

## ✅ Verifica Finale

### Via Web Browser
1. Vai su: https://github.com/pozivo/nextmap/releases
2. Clicca su "v0.3.0"
3. Conta gli assets nella sezione "Assets"
4. Dovrebbero essere **esattamente 4**

### Assets Corretti (v0.3.0)
```
✅ nextmap-linux-x64.tar.gz      (Linux, 64-bit)
✅ nextmap-windows-x64.zip        (Windows, 64-bit)
✅ nextmap-macos-x64.tar.gz       (macOS Intel, 64-bit)
✅ nextmap-macos-arm64.tar.gz     (macOS Apple Silicon)
```

---

## 🎯 Procedura Consigliata

### Step 1: Verifica che il workflow sia aggiornato ✅
```powershell
git log --oneline -1 .github/workflows/release.yml
# Dovrebbe mostrare: 40b5539 🔧 Fix GitHub release workflow
```

### Step 2: Ri-trigger v0.3.0 (Opzione Consigliata)
```powershell
# Salva il commit del tag attuale
git rev-parse v0.3.0

# Elimina e ricrea il tag
git tag -d v0.3.0
git push origin :refs/tags/v0.3.0
git tag v0.3.0 e36367f
git push origin v0.3.0
```

### Step 3: Monitora GitHub Actions
1. Vai su: https://github.com/pozivo/nextmap/actions
2. Guarda il workflow "Release" in esecuzione
3. Attendi completamento (~5-10 minuti)
4. Verifica che la release abbia 4 assets

### Step 4: (Opzionale) Pulisci v0.2.5
Se vuoi anche v0.2.5 pulita:
```powershell
git tag -d v0.2.5
git push origin :refs/tags/v0.2.5
git tag v0.2.5 f1ee1db
git push origin v0.2.5
```

---

## 📝 Checklist

```
Workflow Fix:
- [x] Workflow .github/workflows/release.yml aggiornato
- [x] Commit pushato su GitHub (40b5539)
- [x] Script di cleanup creati

Release v0.3.0:
- [ ] Tag v0.3.0 ricreato (opzionale)
- [ ] Workflow eseguito con successo
- [ ] Verificato 4 assets corretti
- [ ] Nessun asset duplicato

Release v0.2.5:
- [ ] Tag v0.2.5 ricreato (opzionale)
- [ ] Workflow eseguito con successo
- [ ] Verificato 4 assets corretti
- [ ] Nessun asset duplicato

Future Releases:
- [x] Workflow garantisce 4 assets per release future
- [x] Nessun intervento manuale necessario
```

---

## 🎓 Come Funziona il Fix

### Prima (PROBLEMA):
```yaml
files: |
  **/*.zip        # ❌ Cattura TUTTI i .zip
  **/*.tar.gz     # ❌ Cattura TUTTI i .tar.gz
```
**Risultato**: 8+ files (include vecchie versioni dalla cache)

### Dopo (SOLUZIONE):
```yaml
- name: Prepare release files
  run: |
    mkdir -p release-files
    mv nextmap-linux-x64/nextmap-linux-x64.tar.gz release-files/
    mv nextmap-windows-x64/nextmap-windows-x64.zip release-files/
    mv nextmap-macos-x64/nextmap-macos-x64.tar.gz release-files/
    mv nextmap-macos-arm64/nextmap-macos-arm64.tar.gz release-files/

files: |
  release-files/nextmap-linux-x64.tar.gz      # ✅ Specifico
  release-files/nextmap-windows-x64.zip       # ✅ Specifico
  release-files/nextmap-macos-x64.tar.gz      # ✅ Specifico
  release-files/nextmap-macos-arm64.tar.gz    # ✅ Specifico
```
**Risultato**: Esattamente 4 files (solo versione corrente)

---

## ❓ FAQ

### Q: Perché le release hanno asset duplicati?
**A**: Il workflow usava `**/*.zip` che catturava TUTTI i file .zip, inclusi quelli da build precedenti nella cache.

### Q: Il fix risolverà le release esistenti?
**A**: No, il fix è solo per release future. Le release esistenti vanno pulite manualmente o ri-triggerate.

### Q: Devo ricreare tutte le release?
**A**: No, solo quelle con asset duplicati (v0.2.5, v0.3.0). Le release future saranno automaticamente corrette.

### Q: Cosa succede se ri-triggero il tag?
**A**: GitHub Actions ricostruirà i binari e aggiornerà la release con solo 4 assets corretti.

### Q: Posso lasciare le release come sono?
**A**: Sì, ma gli utenti potrebbero scaricare binari obsoleti. Meglio pulirle.

---

## 🚀 Comando Rapido (TL;DR)

### Per pulire e ricreare v0.3.0:
```powershell
git tag -d v0.3.0
git push origin :refs/tags/v0.3.0
git tag v0.3.0 e36367f
git push origin v0.3.0
```

### Per verificare su GitHub:
https://github.com/pozivo/nextmap/releases/tag/v0.3.0

Dovrebbero esserci **esattamente 4 assets**.

---

**✅ Fix implementato!**  
**🔄 Release future automaticamente corrette!**  
**🧹 Release esistenti: Pulizia opzionale via web o re-trigger**
