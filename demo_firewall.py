from src.db_firewall import DBFirewall

print("🛡️ Starting Database Request Firewall Simulation...")
fw = DBFirewall()

print("\n[TEST 1] Simulating a SAFE logging request...")
# This represents the normal system trying to read or insert logs
success, msg = fw.execute_safe_query("SELECT * FROM attack_logs LIMIT 1")
if success:
    print("✅ Result: ALLOWED (Normal Operation)")
else:
    print(f"❌ Result: BLOCKED -> {msg}")

print("\n[TEST 2] Simulating a MALICIOUS query (Attacker trying to delete logs)...")
# This represents a compromised module or direct SQL injection attempt
success, msg = fw.execute_safe_query("DROP TABLE attack_logs")
if success:
    print("✅ Result: ALLOWED")
else:
    print(f"❌ Result: BLOCKED -> {msg}")

print("\n[TEST 3] Simulating an UNAUTHORIZED record modification...")
success, msg = fw.execute_safe_query("DELETE FROM attack_logs WHERE id=1")
if success:
    print("✅ Result: ALLOWED")
else:
    print(f"❌ Result: BLOCKED -> {msg}")

print("\n🏁 Simulation Complete! Please refresh your Streamlit Security Dashboard.")