#!/bin/bash

# Test script per NextMap v0.2.1 - Comportamento nmap-style
# Testa i nuovi preset di porte e comportamenti

echo "🧪 NextMap v0.2.1 - Test Suite (nmap-style behavior)"
echo "======================================================"

# Verifiche base
echo ""
echo "📋 VERIFICHE COMPORTAMENTO NMAP-STYLE:"
echo ""

echo "✅ Default ports: top1000 (come nmap)"
echo "✅ Preset disponibili: top100, top1000, all"
echo "✅ Avvisi intelligenti per scansioni grandi"
echo "✅ Output informativo su numero porte"

echo ""
echo "🔧 TEST CASES DA VERIFICARE:"
echo ""

echo "1. TEST DEFAULT BEHAVIOR:"
echo "   nextmap --target 127.0.0.1"
echo "   → Dovrebbe scansionare 1000 porte (top1000)"
echo ""

echo "2. TEST PRESET TOP100:"
echo "   nextmap --target 127.0.0.1 --ports \"top100\""
echo "   → Dovrebbe scansionare 100 porte comuni"
echo ""

echo "3. TEST PRESET ALL:"
echo "   nextmap --target 127.0.0.1 --ports \"all\""
echo "   → Dovrebbe mostrare WARNING e scansionare tutte 65535 porte"
echo ""

echo "4. TEST CUSTOM PORTS:"
echo "   nextmap --target 127.0.0.1 --ports \"80,443,22\""
echo "   → Dovrebbe scansionare solo 3 porte custom"
echo ""

echo "5. TEST RANGE PORTS:"
echo "   nextmap --target 127.0.0.1 --ports \"1-1000\""
echo "   → Dovrebbe scansionare porte 1-1000"
echo ""

echo ""
echo "🎯 COMPORTAMENTI ATTESI:"
echo ""
echo "• DEFAULT: top1000 (1000 porte) - nessun warning"
echo "• top100: 100 porte - nessun warning"
echo "• all: 65535 porte - WARNING con suggerimenti"
echo "• 5000+ porte: WARNING large range"
echo "• Custom/Range: numero porte specificate"

echo ""
echo "📊 OUTPUT INFORMATIVI ATTESI:"
echo ""
echo "• '🔍 TCP Ports: 1000 (top 1000 common ports - nmap default)'"
echo "• '🔍 TCP Ports: 100 (top 100 common ports)'"
echo "• '🔍 TCP Ports: 65535 (all ports)'"
echo "• '🔍 TCP Ports: X custom ports'"

echo ""
echo "⚠️  WARNING MESSAGES:"
echo ""
echo "• Full port scan: 'WARNING: Full port scan (1-65535) detected!'"
echo "• Large range: 'WARNING: Large port range (X ports)'"
echo "• Suggerimenti: 'TIP: Consider using --ports \"top1000\"'"

echo ""
echo "🚀 READY FOR MANUAL TESTING!"
echo "Compila ed esegui i test cases sopra per verificare il comportamento."