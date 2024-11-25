import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread
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
                        
                        # Извлечение уязвимостей из вывода скрипта
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
        return {"error": str(e)}

    return scan_results

# ====== Функция для парсинга уязвимостей ======
def parse_vulnerabilities(vulners_output):
    vulnerabilities = []
    lines = vulners_output.splitlines()
    
    for line in lines:
        # Используем регулярное выражение для поиска ID уязвимости, CVSS и ссылки
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
    report_lines = []
    for host, data in scan_results.items():
        hostname = data.get("hostname", "Неизвестно")
        report_lines.append(f"Хост: {host} ({hostname})")
        
        services = data.get("services", [])
        if services:
            for service in services:
                report_lines.append(f"  Порт: {service['port']}/{service['protocol']}")
                report_lines.append(f"  Сервис: {service['service']} {service['version']}")
                
                vulnerabilities = service['vulnerabilities']
                if vulnerabilities:
                    report_lines.append(f"  Найдено уязвимостей: {len(vulnerabilities)}")
                    for vuln in vulnerabilities:
                        report_lines.append(f"    - ID: {vuln['id']} (CVSS: {vuln['cvss']})")
                        report_lines.append(f"      Ссылка: {vuln['link']}")
                else:
                    report_lines.append("    Уязвимости не найдены.")
        else:
            report_lines.append("  Открытые порты не найдены.")
        report_lines.append("-" * 40)

    return "\n".join(report_lines)

# Функция для обработки сканирования
def start_scan():
    target_input = ip_entry.get().strip()  # Получаем введённый IP-адрес или диапазон
    if not target_input:
        messagebox.showwarning("Предупреждение", "Пожалуйста, введите хотя бы один IP-адрес.")
        return

    # Разделяем адреса по пробелам
    targets = target_input.split()
    
    # Запускаем сканирование в отдельном потоке
    scan_thread = Thread(target=perform_scan, args=(targets,))
    scan_thread.start()

def perform_scan(targets):
    loading_label.pack(pady=20)
    root.update()

    # Итоговый отчёт для всех IP-адресов
    full_report = ""

    for target in targets:
        # Выполняем сканирование текущего адреса
        scan_results = scan_network(target)
        if "error" in scan_results:
            full_report += f"Сканирование {target} завершилось ошибкой: {scan_results['error']}\n"
        else:
            # Генерируем отчёт для текущего адреса
            full_report += generate_report(scan_results)
            full_report += "\n" + "=" * 50 + "\n"  # Разделитель между результатами

    # Отображаем результат
    root.after(0, lambda: display_report(full_report))

def display_report(report):
    result_text.delete(1.0, tk.END)  # Очищаем текстовое поле перед выводом нового отчета
    result_text.insert(tk.END, report)
    loading_label.pack_forget()  # Скрываем сообщение после завершения

# Создание основного окна
root = tk.Tk()
root.title("Инструмент сетевого сканирования и анализа уязвимостей")
root.geometry("900x700")  # Размер окна увеличен
root.config(bg="#222831")

# Настройка стилей для ttk
style = ttk.Style()
style.configure("TButton",
                font=("Helvetica", 12, "bold"),
                background="#00ADB5",
                padding=12,
                relief="flat",
                foreground="black")  # Изменён текст на чёрный для контраста

style.map("TButton",
          background=[("active", "#00B5B8")])

style.configure("TLabel",
                font=("Helvetica", 12),
                background="#222831",
                foreground="#EEEEEE")

style.configure("TEntry",
                font=("Helvetica", 12),
                padding=8,
                relief="flat",
                foreground="#333333",
                background="#EEEEEE")

style.configure("TFrame",
                background="#222831")

# Создаем элементы интерфейса
frame = ttk.Frame(root, padding="20", relief="solid", borderwidth=2, style="TFrame")
frame.pack(padx=20, pady=10, fill="x")

# Создаем надпись для ввода IP
ip_label = ttk.Label(frame, text="Введите IP-адреса или диапазоны через пробел (например, 192.168.1.1 192.168.1.2/24):")
ip_label.grid(row=0, column=0, columnspan=2, pady=5, sticky="w")

# Поле ввода для IP-адресов
ip_entry = ttk.Entry(frame, width=40)
ip_entry.grid(row=1, column=0, columnspan=2, pady=5, sticky="ew")

# Кнопка для запуска сканирования
scan_button = ttk.Button(frame, text="Начать сканирование", command=start_scan)
scan_button.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

# Окно для отображения результатов сканирования
result_text = tk.Text(root, width=100, height=30, font=("Courier New", 12), bg="#393E46", fg="#EEEEEE", padx=10, pady=10)
result_text.pack(padx=20, pady=10, fill="both", expand=True)

# Добавление прокрутки
scrollbar = tk.Scrollbar(result_text)
scrollbar.pack(side="right", fill="y")
result_text.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=result_text.yview)

# Заглушка для GIF загрузки
loading_label = tk.Label(root, text="Сканирование выполняется...", bg="#222831", fg="#EEEEEE", font=("Helvetica", 14, "italic"))

# Запуск главного цикла интерфейса
root.mainloop()