################################################################
#                                                              #
#               Program to scan a domain/IP @                  #
#                       using NMAP                             #
#                                                              #
#               use scanme.nmap.org  to test                   #
#                                                              #
################################################################


import nmap


def scan_ports(target, ports):
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
#looping on all  hosts detected by NMAP
    for i in scanner.all_hosts():
        print(f"\n📡 result for {i}:")
        print(f"  - State : {scanner[i].state()}")  # up/down

        #looping on protocols
        for y in scanner[i].all_protocols():
            print(f"  -Protocol: {y}")

            #listing open ports
            open_ports=scanner[i][y].keys()
            for port in sorted(open_ports):
                service = scanner[i][y][port]['name']  # service
                print(f"    - Port {port} : OPEN ({service})")


#T = input("Enter an IP @ or a Domain to scan : ")
#scan_ports(T)

scan_ports("scanme.nmap.org", "1-1024")
