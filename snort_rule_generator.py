def generate_sql_injection_rules(protocol, src_ip, dest_ip, dest_port, message, sid):
    patterns = [
        "' OR '1'='1",
        "UNION SELECT",
        "--",
        ";--",
        "/*",
        "xp_cmdshell",
        "SELECT * FROM",
        "DROP TABLE",
        "' OR 'a'='a"
    ]
    rules = [
        f"alert {protocol} {src_ip} any -> {dest_ip} {dest_port} (msg: \"{message}\"; content: \"{pattern}\"; nocase; sid: {sid + i};)"
        for i, pattern in enumerate(patterns)
    ]
    return "\n".join(rules)

def generate_idor_rules(protocol, src_ip, dest_ip, dest_port, message, sid):
    patterns = [
        "/user?id=",
        "/account?id=",
        "/order?id=",
        "/profile?id=",
        "/admin?id="
    ]
    rules = [
        f"alert {protocol} {src_ip} any -> {dest_ip} {dest_port} (msg: \"{message}\"; content: \"{pattern}\"; nocase; sid: {sid + i};)"
        for i, pattern in enumerate(patterns)
    ]
    return "\n".join(rules)

def generate_xss_rules(protocol, src_ip, dest_ip, dest_port, message, sid):
    patterns = [
        "<script>",
        "</script>",
        "javascript:",
        "onerror=",
        "onload=",
        "<img src=",
        "document.cookie",
        "<iframe",
        "alert("
    ]
    rules = [
        f"alert {protocol} {src_ip} any -> {dest_ip} {dest_port} (msg: \"{message}\"; content: \"{pattern}\"; nocase; sid: {sid + i};)"
        for i, pattern in enumerate(patterns)
    ]
    return "\n".join(rules)

def generate_dos_rules(protocol, src_ip, dest_ip, dest_port, message, sid):
    rules = [
        f"alert {protocol} {src_ip} any -> {dest_ip} {dest_port} (msg: \"{message}\"; detection_filter: track by_src, count 50, seconds 10; sid: {sid};)"
    ]
    return "\n".join(rules)

def generate_telnet_rules(protocol, src_ip, dest_ip, dest_port, message, sid):
    patterns = [
        "\xFF\xFB\x01",  # Telnet DoS attack pattern
        "\xFF\xFB\x03",
        "\xFF\xFD\x18"
    ]
    rules = [
        f"alert {protocol} {src_ip} any -> {dest_ip} {dest_port} (msg: \"{message}\"; content: \"{pattern}\"; sid: {sid + i};)"
        for i, pattern in enumerate(patterns)
    ]
    return "\n".join(rules)

def main():
    print("******************************************")
    print("********* SNORT RULE AUTOMATION **********")
    print("****** DESIGNED BY: YASH THAKARE *******")
    print("******************************************\n")

    print("Welcome to Snort Rule Generator!\n")
    print("Select the vulnerability type:")
    print("0. SQL Injection (SQL)")
    print("1. Insecure Direct Object Reference (IDOR)")
    print("2. Cross-Site Scripting (XSS)")
    print("3. Denial of Service (DOS)")
    print("4. Telnet")

    # Input for vulnerability type
    vuln_type_num = int(input("Enter the vulnerability type number (0-4): "))
    vulnerabilities = ["SQL", "IDOR", "XSS", "DOS", "Telnet"]
    if vuln_type_num not in range(len(vulnerabilities)):
        print("Invalid selection. Please enter a number between 0 and 4.")
        return

    vuln_type = vulnerabilities[vuln_type_num]

    # Inputs for rule creation
    protocol = input("Enter the protocol (e.g., tcp): ")
    src_ip = input("Enter the source IP address (e.g., any): ")
    dest_ip = input("Enter the destination IP address: ")
    dest_port = input("Enter the destination port: ")
    message = input(f"Enter the message for the rule (e.g., '{vuln_type} attack detected'): ")
    sid = int(input("Enter the SID for the rule (must be unique): "))

    # Generate the rules based on the selected vulnerability type
    if vuln_type == "SQL":
        rules = generate_sql_injection_rules(protocol, src_ip, dest_ip, dest_port, message, sid)
    elif vuln_type == "IDOR":
        rules = generate_idor_rules(protocol, src_ip, dest_ip, dest_port, message, sid)
    elif vuln_type == "XSS":
        rules = generate_xss_rules(protocol, src_ip, dest_ip, dest_port, message, sid)
    elif vuln_type == "DOS":
        rules = generate_dos_rules(protocol, src_ip, dest_ip, dest_port, message, sid)
    elif vuln_type == "Telnet":
        rules = generate_telnet_rules(protocol, src_ip, dest_ip, dest_port, message, sid)

    # Output the generated rules
    print("\nRule(s) generated successfully!\n")
    print("Here are your Snort rule(s):")
    print(rules)

if __name__ == "__main__":
    main()

