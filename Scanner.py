import nmap


#regular expression pattern to recognise IPv4 addresses
#ip_add_pattern = re.compile("^(?:[0-9]){1,3}\.){3}[0-9]{1,3}$")

def scan_ports(target, ports= "1-1024"):
    """

    :param target: IP address or server name domain
    :param ports: range of ports to scan
    """

    scanner = nmap.PortScanner() #we create our scanner

    print(f"Scanning on {target}, ports: {ports}...")

    scanner.scan(target, ports, arguments="-sS -T4 --open") #we start a scan using the parameters of the function
    """
    :argument personalizing the scan:
        -sS Scan SYN use SYN packets to detect open ports without establishing a complete connection (less detectable by firewall though)
        -T4 scan speed: fast but relatively noise less
        --open prints only open ports and not closed/filtered
    """


