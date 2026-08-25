import ipaddress #Needed for identifying IP addresses

print("\nSSH-Auth-Log-Analyzer")
print("\nAnalyzing log file line by line...")

failed_login = 0 #Initialize variable
ip_counts = {} #Dictionary maps address to no. of attempts
BRUTE_FORCE_THRESHOLD = 5 #5 or more failed passwords is potential Brute Force 

with open("auth.log", "r") as log:
    for line in log:
        line = line.lower()

        if "failed password" in line:
            failed_login += 1 #Add 1 to total of failed logins

            for word in line.split():
                try:
                    ip = ipaddress.ip_address(word) #Is a word an IP address?

                    if ip in ip_counts:
                        ip_counts[ip] += 1 #Add 1 to value if key (address) is recorded
                    else:
                        ip_counts[ip] = 1 #Set value to 1 if key (address) is new

                except ValueError:
                    pass

print("\nThere were a total of", failed_login, "failed password entries.")

for address, count in sorted(ip_counts.items()): #Iterate through dictionary
    print(f"\n{count} failed password entries came from {address}")
    if count >= BRUTE_FORCE_THRESHOLD: #If Brute Force threshold is met
        print(f"\nPotential Brute Force attempt from IPv4 Address: {address}")
