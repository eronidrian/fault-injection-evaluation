import csv

with open("/home/petr/Downloads/fault_injection/mbed_tls/mbedtls_p256m_results.txt", "r") as f:
    content = f.read().splitlines()

attack_names = ["Loop abort output", "Faulted key", "Fixed output"]

library_name = "mbedtls_p256m"
f = open(f"{library_name}_results.csv", "w")
output = csv.writer(f)

output.writerow(["Attack type", "Address", "Change", "Output", "Bits of security"])

for line in content[1:]:
    if not line:
        continue
    if line.startswith("Total number"):
        break
    if line.startswith(tuple(attack_names)):
        attack_type = line.split("-")[0].strip()
        attack_output = line.split("-")[1].strip().split(" ")[0].strip()
        bits_of_security = line.split("-")[1].strip().split(" ")[1].strip()
        bits_of_security = bits_of_security.replace("(", "")
        bits_of_security = bits_of_security.replace(")", "")
        bits_of_security = bits_of_security.replace(".", "")
    else:
        address = line.split(" ")[1].strip()
        change = line.split(" - ")[1].strip()
        output.writerow([attack_type, address, change, attack_output, bits_of_security])