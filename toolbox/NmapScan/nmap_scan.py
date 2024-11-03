import argparse
import nmap
import os

def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True

def scan_ip(ip_addresses):
    scanner = nmap.PortScanner()
    scan_results = ""
    found_results = False  

    for ip in ip_addresses:
        if not is_valid_ip(ip):
            scan_results += f"\nIP-adressen {ip} är ogiltig.\n"
            continue

        try:
            print(f"\nSkannar IP-adress: {ip}...")
            scanner.scan(ip, '1-1024', '-sV')

            if ip in scanner.all_hosts():
                found_results = True
                scan_results += f"\nResultat för {ip}:\n"
                for proto in scanner[ip].all_protocols():
                    ports = scanner[ip][proto].keys()
                    for port in ports:
                        state = scanner[ip][proto][port]['state']
                        service = scanner[ip][proto][port]['name']
                        version = scanner[ip][proto][port].get('version', 'okänd')
                        scan_results += f"Port: {port}\tState: {state}\tService: {service}\tVersion: {version}\n"
                scan_results += "\n"
            else:
                scan_results += f"Inga resultat för {ip}. IP-adressen verkar inte vara tillgänglig eller nere.\n\n"
        except Exception as e:
            scan_results += f"Fel vid skanning av {ip}: {str(e)}\n\n"

    return scan_results if found_results else None

def save_to_file(data, filename="scan_results.txt"):
    if not filename.strip():
        print("Ogiltigt filnamn. Försök igen.")
        return False
    with open(filename, 'w') as file:
        file.write(data)
    print(f"Resultaten sparades till filen: {filename}")
    return True

def load_ips_from_file(filename):
    if not os.path.exists(filename):
        print("Filen finns inte.")
        return []

    with open(filename, 'r') as file:
        ips = file.read().splitlines()
    return ips

def main():
    parser = argparse.ArgumentParser(description="Skanna IP-adresser och spara resultat.")
    parser.add_argument("--ips", nargs="+", help="Ange IP-adresser att skanna")
    parser.add_argument("--file", help="Fil att läsa IP-adresser från")
    parser.add_argument("--save", help="Fil att spara resultat i")

    args = parser.parse_args()

    
    if args.ips or args.file:
        ips = args.ips if args.ips else load_ips_from_file(args.file)
        if not ips:
            print("Inga giltiga IP-adresser angivna.")
            return

        scan_results = scan_ip(ips)
        if scan_results:
            print(scan_results)
            if args.save:
                save_to_file(scan_results, args.save)
            else:
                print("Ingen sparfil angiven, resultat visas bara.")
        else:
            print("Inga resultat att spara.")
    else:
        
        while True:
            print("\nMeny:")
            print("1. Ange IP-adresser manuellt")
            print("2. Läs IP-adresser från fil")
            print("3. Skanna IP-adresser")
            print("4. Avsluta")

            choice = input("Välj ett alternativ (1-4): ")

            if choice == '1':
                ips = input("Ange IP-adresser: ").split()
            elif choice == '2':
                filename = input("Ange filnamnet som innehåller IP-adresser: ")
                ips = load_ips_from_file(filename)
            elif choice == '3':
                if 'ips' not in locals() or len(ips) == 0:
                    print("Du måste först ange eller ladda IP-adresser.")
                    continue

                scan_results = scan_ip(ips)
                if scan_results:
                    print(scan_results)
                    save_choice = input("Vill du spara resultaten till en fil? (j/n): ").lower()
                    if save_choice == 'j':
                        while True:
                            save_filename = input("Ange ett filnamn för att spara resultaten (t.ex. scan_results.txt): ")
                            if save_to_file(scan_results, save_filename):
                                break
                else:
                    print("Inga giltiga resultat att spara.")
                    
            elif choice == '4':
                print("Avslutar programmet...")
                break
            else:
                print("Ogiltigt val. Försök igen.")

if __name__ == "__main__":
    main()

