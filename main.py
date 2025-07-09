import os
import sys

def print_banner():
    ORANGE = "\033[1;91m"  
    RESET = "\033[0m"

    print(ORANGE + r"""
    
__      ___    _ _      _   _        _____  ______ _______ ______ _____ _______ ____  _____  
\ \    / / |  | | |    | \ | |      |  __ \|  ____|__   __|  ____/ ____|__   __/ __ \|  __ \ 
 \ \  / /| |  | | |    |  \| |______| |  | | |__     | |  | |__ | |       | | | |  | | |__) |
  \ \/ / | |  | | |    | . ` |______| |  | |  __|    | |  |  __|| |       | | | |  | |  _  / 
   \  /  | |__| | |____| |\  |      | |__| | |____   | |  | |___| |____   | | | |__| | | \ \ 
    \/    \____/|______|_| \_|      |_____/|______|  |_|  |______\_____|  |_|  \____/|_|  \_\
                
                    ----------VULN-DETECTOR - OWASP Security Suite---------- 
                    
""" + RESET)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_menu():
    print("==== Security Assessment Tool Menu ====")
    print("1. XSS Scanner")
    print("2. Html injector")
    print("3. Java Script injector")
    print("4. Sqli injector")
    print("5. XSS injector")
    print("6. Cryptographic failure Checker")
    print("7. Security Misconfiguration & Nmap Scanner")
    print("8. Broken link")
    print("9. SSRF Detector")
    print("0. Exit")

def run_xss_scanner():
    os.system("python xss_scanner.py")

def run_htmlinjector():
    os.system("python htmlinjector.py")

def run_jsinjector():
    os.system("python jsinjector.py")

def run_sqliinjector():
    os.system("python sqliinjector.py")

def run_xssinjector():
    os.system("python xssinjector.py")

def run_cryp_fail_checker():
    os.system("python cryp_fail_checker.py")

def run_misconfig_nmap():
    os.system("python security_misconfig.py")

def run_brokenlink():
    os.system("python brokenlink.py")

def run_ssrf_detector():
    os.system("python ssrf_detector.py")

def main():
    clear()             
    print_banner()      

    while True:
        print_menu()   
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            run_xss_scanner()
        elif choice == "2":
            run_htmlinjector()
        elif choice == "3":
            run_jsinjector()
        elif choice == "4":
            run_sqliinjector()
        elif choice == "5":
            run_xssinjector()
        elif choice == "6":
            run_cryp_fail_checker()
        elif choice == "7":
            run_misconfig_nmap()
        elif choice == "8":
            run_brokenlink()
        elif choice == "9":
            run_ssrf_detector()
        elif choice == "0":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid choice. Try again.")
        
        input("\nPress Enter to return to menu...\n")

if __name__ == "__main__":
    main()
