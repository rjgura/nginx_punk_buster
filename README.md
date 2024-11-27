# nginx_punk_buster

Are you troubled by strange nuisances in the middle of the night?
Do you experience feelings of dread looking in your nginx log?
Have you or your family ever seen a spoof or scan on your host?
If the answer is "yes," then don't wait another minute. Pick up the phone and call the professionals...

nginx_punk_buster.

Our courteous and efficient staff is on call 2 to 4 hours a day (script has higher availability) to serve all your penetration elimination needs.
We're ready to relieve you.

# What it Actually Does

1. Automates pulling suspicious nginx log entries
2. Checks them against the [AbuseIPDB.](https://www.abuseipdb.com/)
3. Update a firewall group (blacklist) for Ubiquiti equipment via their network controller
4. Create a csv of the IP addresses

# Installation

1. Copy files to location
2. Edit nginx_punk_buster.py to configure locations of files (absolute, not relative)
3. Update known_ips.json with any known addresses you want to skip
4. Update credentials in Settings.ini
5. Automate with Cron or Windows Scheduled Task