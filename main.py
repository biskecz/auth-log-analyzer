# Login statistics
success = 0
failed = 0

# Store unique IP addresses
ips = set()

# Failed login attempts per IP
failed_ips = {}

# Most suspicious IP
max_ip = ""
max_attempts = 0

# Read and analyze log file
with open("auth.log", "r") as file:
    for line in file:
        line = line.strip()

        parts = line.split()

        status = parts[2]
        ip = parts[4]

        # Save unique IP
        ips.add(ip)

        # Count successful and failed logins
        if status == "LOGIN_SUCCESS":
            success += 1
        else:
            failed += 1

        # Count failed attempts for every IP
        if status == "LOGIN_FAILED":
            if ip not in failed_ips:
                failed_ips[ip] = 1
            else:
                failed_ips[ip] += 1

# Find the IP with the most failed attempts
for ip, count in failed_ips.items():
    if count > max_attempts:
        max_attempts = count
        max_ip = ip

# ==========================
# Report
# ==========================

print("=" * 35)
print("        AUTH LOG REPORT")
print("=" * 35)

print(f"Successful logins : {success}")
print(f"Failed logins     : {failed}")
print(f"Suspicious IP     : {max_ip}")
print(f"Failed attempts   : {max_attempts}")

print("\nFailed logins by IP:")
print("-" * 35)

for ip, count in sorted(
    failed_ips.items(),
    key=lambda item: item[1],
    reverse=True
):
    print(f"{ip:<15} : {count}")

print("\nUnique IP addresses:")
print("-" * 35)

for ip in sorted(ips):
    print(ip)

print("\nPossible brute-force attacks:")
print("-" * 35)

for ip, count in failed_ips.items():
    if count >= 10:
        print(f"[ALERT] {ip} -> {count} failed attempts")

print("\nAnalysis completed.")