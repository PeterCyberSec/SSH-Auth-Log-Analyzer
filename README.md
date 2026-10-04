# SSH-Auth-Log-Analyzer
A Python project for analyzing SSH authentication logs and identifying potential brute-force attempts.

Each login attempt has its source IPv4 address recorded. This provides the ability to determine how many failed login attempts originated from a single IPv4 address, and if there are more than five then a potential brute force attack is detected and a warning is displayed on screen.
