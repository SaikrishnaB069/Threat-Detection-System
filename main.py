import re
import requests
from datetime import datetime

log_file = "logs/auth.log"

failed_login_count = {}
scan_count = {}
alerts = []

# Telegram details
bot_token = "8769889869:AAHyqJWU3O_7Wm2yQAivMVNtxPBJJ6hGyT8"
chat_id = "1076568053"


with open(log_file, "r") as file:
    logs = file.readlines()


for line in logs:

    if "Failed password" in line:

        match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)

        if match:
            ip = match.group(1)

            if ip in failed_login_count:
                failed_login_count[ip] += 1
            else:
                failed_login_count[ip] = 1


    if "scanned port" in line:

        match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)

        if match:
            ip = match.group(1)

            if ip in scan_count:
                scan_count[ip] += 1
            else:
                scan_count[ip] = 1


for ip in failed_login_count:

    if failed_login_count[ip] >= 3:
        alerts.append("[HIGH] Possible brute-force attack from " + ip)


for ip in scan_count:

    if scan_count[ip] >= 3:
        alerts.append("[MEDIUM] Possible port scan detected from " + ip)


print("\nAlerts Found:\n")

for item in alerts:
    print(item)


# Send Telegram alerts
for item in alerts:

    url = "https://api.telegram.org/bot" + bot_token + "/sendMessage"

    data = {
        "chat_id": chat_id,
        "text": item
    }

    requests.post(url, data=data)


# Save report
time_now = datetime.now().strftime("%Y%m%d_%H%M%S")
report_file = "reports/report_" + time_now + ".txt"

with open(report_file, "w") as file:

    file.write("Threat Detection Report\n\n")

    if len(alerts) == 0:
        file.write("No threats detected")
    else:
        for item in alerts:
            file.write(item + "\n")


print("\nReport saved:", report_file)
print("Telegram alerts sent.")