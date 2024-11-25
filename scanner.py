import nmap
import socket
import re

# ====== Функция для сканирования сети ======
def scan_network(ip_range):
    nm = nmap.PortScanner()
    scan_results = {}

    print(f"Сканирование диапазона: {ip_range}")
    try:
        # Используем скрипт vulners для получения уязвимостей
        nm.scan(hosts=ip_range, arguments='-sV --script vulners --script-args mincvss=5.0 -Pn -T4')

        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                services = []
                try:
                    hostname = socket.gethostbyaddr(host)[0]
                except socket.herror:
                    hostname = "Неизвестно"
                
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        service_name = nm[host][proto][port]['name']
                        service_version = nm[host][proto][port].get('version', 'Unknown')
                        
                        # Extract vulnerabilities from the script output
                        vulners_output = nm[host][proto][port].get('script', {}).get('vulners', '')
                        vulnerabilities = parse_vulnerabilities(vulners_output)
                        
                        services.append({
                            'port': port,
                            'protocol': proto,
                            'service': service_name,
                            'version': service_version,
                            'vulnerabilities': vulnerabilities
                        })
                
                scan_results[host] = {
                    "hostname": hostname,
                    "services": services
                }

    except Exception as e:
        print(f"Ошибка сканирования сети: {e}")
        return {}

    return scan_results

# ====== Функция для парсинга уязвимостей ======
def parse_vulnerabilities(vulners_output):
    vulnerabilities = []
    lines = vulners_output.splitlines()
    
    for line in lines:
        # Use regex to find vulnerability ID, CVSS score, and link
        match = re.findall(r'(\S+)\s+(\d+\.\d+)\s+(https?://\S+)', line)
        if match:
            for vuln_id, cvss_score, link in match:
                vulnerabilities.append({
                    'id': vuln_id,
                    'cvss': cvss_score,
                    'link': link
                })
    
    return vulnerabilities

# ====== Генерация отчета ======
def generate_report(scan_results):
    print("\n=== Отчет о сканировании ===\n")
    for host, data in scan_results.items():
        hostname = data.get("hostname", "Неизвестно")
        print(f"Хост: {host} ({hostname})")
        
        services = data.get("services", [])
        if services:
            for service in services:
                print(f"  Порт: {service['port']}/{service['protocol']}")
                print(f"  Сервис: {service['service']} {service['version']}")
                
                vulnerabilities = service['vulnerabilities']
                if vulnerabilities:
                    print(f"  Найдено уязвимостей: {len(vulnerabilities)}")
                    for vuln in vulnerabilities:
                        print(f"    - ID: {vuln['id']} (CVSS: {vuln['cvss']})")
                        print(f"      Ссылка: {vuln['link']}")
                else:
                    print("    Уязвимости не найдены.")
        else:
            print("  Открытые порты не найдены.")
        print("-" * 40)

# ====== Основной блок программы ======
if __name__ == "__main__":
    print("=== Инструмент сетевого сканирования и анализа уязвимостей ===")
    
    target = input("Введите IP-адрес или диапазон (например, 192.168.1.1/24): ")

    # Выполнение сетевого сканирования
    scan_results = scan_network(target)

    # Генерация отчёта
    generate_report(scan_results)