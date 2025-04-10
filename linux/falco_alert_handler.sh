#!/bin/bash

# Extract alert details from Falco
read falco_alert

# Log Falco alert
echo "$(date) - Falco Alert: $falco_alert" >> /var/log/falco_response.log

# Extract IP or User from the alert message (adjust parsing as needed)
attacker_ip=$(echo "$falco_alert" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
malicious_user=$(echo "$falco_alert" | grep -oP 'User account creation detected: \K\S+')

# Block attacker IP (if found)
if [[ ! -z "$attacker_ip" ]]; then
  iptables -A INPUT -s "$attacker_ip" -j DROP
  echo "$(date) - Blocked attacker IP: $attacker_ip" >> /var/log/falco_response.log
fi

# Kill suspicious user sessions
if [[ ! -z "$malicious_user" ]]; then
  pkill -KILL -u "$malicious_user"
  echo "$(date) - Killed session for: $malicious_user" >> /var/log/falco_response.log
fi

# Send alert to Splunk (adjust Splunk HEC URL)
curl -k "https://splunk-server:8088/services/collector" \
     -H "Authorization: Splunk YOUR_SPLUNK_TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"event\": \"Falco Alert: $falco_alert\"}"

exit 0
