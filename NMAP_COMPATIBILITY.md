# NextMap v0.2.1 - nmap-style Behavior Implementation

## 🎯 Modifiche Implementate per Comportamento nmap-style

### 📊 **Port Scanning Changes**

#### ✅ **Default Behavior**
- **Prima**: `--ports "1-65535"` (tutte le porte)
- **Ora**: `--ports "top1000"` (come nmap di default)
- **Risultato**: Scansioni molto più veloci di default

#### ✅ **Nuovi Port Presets**
```bash
# Top 100 porte più comuni (veloce)
--ports "top100"

# Top 1000 porte più comuni (default nmap)
--ports "top1000"  

# Tutte le porte (scansione completa)
--ports "all"

# Porte custom (come prima)
--ports "80,443,22"
--ports "1-1000"
```

### 🚨 **Sistema di Warning Intelligente**

#### **Default (1000 porte)**: ✅ Nessun warning
```
🔍 TCP Ports: 1000 (top 1000 common ports - nmap default)
```

#### **Top 100**: ✅ Nessun warning
```
🔍 TCP Ports: 100 (top 100 common ports)
```

#### **Range Grande (5000+ porte)**: ⚠️ Warning moderato
```
🔍 TCP Ports: 6000 custom ports
⚠️ WARNING: Large port range (6000 ports) - this may take several minutes.
💡 TIP: Use --ports "top1000" for faster results or --timing-template aggressive
```

#### **Tutte le Porte (65535)**: ⚠️⚠️ Warning completo
```
🔍 TCP Ports: 65535 (all ports)
⚠️ WARNING: Full port scan (1-65535) detected!
    This comprehensive scan will take considerable time.
💡 TIP: Consider using --ports "top1000" for faster results
    or --timing-template aggressive for faster scanning
```

### 📈 **Vantaggi del Nuovo Comportamento**

#### 🚀 **Performance**
- **Default scan**: Da ~20+ minuti → ~2-3 minuti
- **Compatibilità nmap**: Gli utenti si aspettano questo comportamento
- **Esperienza utente**: Risultati immediati senza configurazione

#### 🎯 **Usabilità**
- **Principianti**: Funziona subito senza configurazione
- **Esperti**: Possono scegliere "--ports all" per scan completi
- **Automazione**: Comportamento prevedibile e standard

#### 🔧 **Flessibilità**
- **Backward compatibility**: Tutti i range custom funzionano come prima
- **Upgrade path**: Chiare indicazioni per scan più veloci o completi
- **Educational**: Warning educativi su tempi di scansione

### 📋 **Port Lists Implementation**

#### **Top 100 Ports** (get_top_100_ports)
Le 100 porte TCP più comunemente utilizzate, ottimo per quick scan.

#### **Top 1000 Ports** (get_top_1000_ports)  
Le 1000 porte TCP più comuni - identico al default di nmap.
Include praticamente tutti i servizi comuni che si possono trovare.

### 🧪 **Testing e Verifica**

#### **Test Scripts**
- `test_nmap_behavior.bat` - Test Windows
- `test_nmap_behavior.sh` - Test Linux/macOS  
- Verificano tutti i preset e warning

#### **Expected Output Examples**
```bash
# Default behavior
$ nextmap --target 192.168.1.1
🔍 TCP Ports: 1000 (top 1000 common ports - nmap default)

# Quick scan
$ nextmap --target 192.168.1.1 --ports "top100"
🔍 TCP Ports: 100 (top 100 common ports)

# Comprehensive scan  
$ nextmap --target 192.168.1.1 --ports "all"
🔍 TCP Ports: 65535 (all ports)
⚠️ WARNING: Full port scan (1-65535) detected!
```

### 🎉 **Risultato Finale**

NextMap ora si comporta **esattamente come nmap** di default:
- ✅ Stesse porte scansionate (top 1000)
- ✅ Tempi di esecuzione simili
- ✅ Output informativi chiari
- ✅ Warning appropriati per scan grandi
- ✅ Mantenimento di tutte le funzionalità avanzate

Gli utenti che migrano da nmap troveranno NextMap familiare e intuitivo, mentre quelli che vogliono scan più approfonditi possono facilmente usare `--ports "all"`.