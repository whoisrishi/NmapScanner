import socket
import nmap

def simple_port_scanner(ip, ports_range):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"Scanning open ports for {ip}...")
    print(''' PORT       SERVICE ''')
    
    [start, end] = ports_range

    for port in range(start, end):
        if s.connect_ex((ip, port)):
            print(f"Port {port} is closed")
        else:
            print(f"Port {port} is open")
    s.close()

def nmap_scanner(ip_addr):
    scanner = nmap.PortScanner()
    print("Welcome, this is a simple Nmap automation tool ")
    print("<---------------------------------------------->")
    
    print("The IP you entered is:", ip_addr.strip())
    resp = input('''\n Please Enter the type of scan you want to run 
                1) SYN ACK Scan
                2) UDP Scan
                3) Comprehensive Scan
                \n
                ''')
    
    print("You have selected option:", resp)
    print("Nmap Version is:", scanner.nmap_version())

    if resp == '1':
        scanner.scan(ip_addr, '1-1024', '-v -sS')
        print(scanner.scaninfo())
        print("IP Status:", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports:", scanner[ip_addr]['tcp'].keys())

    elif resp == '2':
        scanner.scan(ip_addr, '1-1024', '-v -sU')
        print(scanner.scaninfo())
        print("IP Status:", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        if 'udp' in scanner[ip_addr]:
            print("Open Ports:", scanner[ip_addr]['udp'].keys())
        else:
            print("No open UDP ports found.")

    elif resp == '3':
        scanner.scan(ip_addr, '1-1024', '-v -sU -sS -sV -A -O')
        print(scanner.scaninfo())
        print("IP Status:", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        if 'tcp' in scanner[ip_addr]:
            print("Open Ports:", scanner[ip_addr]['tcp'].keys())
        else:
            print("No open TCP ports found.")
    else:
        print("Enter a valid input.")

def main():
    print("Select an option:")
    print("1) Simple Port Scanner")
    print("2) Nmap Scanner")
    
    choice = input("Enter your choice (1 or 2): ")

    if choice == '1':
        ip = input("Please enter the IP address you want to scan: ")
        ports_range = [int(x) for x in input("Enter the port range (e.g., 80-90): ").split('-')]
        simple_port_scanner(ip, ports_range)
    elif choice == '2':
        ip_addr = input("Please enter the IP address you want to scan: ")
        nmap_scanner(ip_addr)
    else:
        print("Invalid choice. Please select 1 or 2.")

if __name__ == "__main__":
    main()
