import socket

def get_service_info(ip, ports):
    service_info = {}
    for port in ports:
        try:
            # Создаем сокет
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Устанавливаем таймаут для подключения
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Если соединение успешно, пробуем получить информацию о сервисе
                service_info[port] = "open"
            else:
                service_info[port] = "closed"
        except Exception as e:
            service_info[port] = f"error: {str(e)}"
        finally:
            sock.close()
    
    return service_info

# Укажите IP-адрес и список портов для проверки
ip_address = "193.41.142.172"
open_ports = [53, 80, 443, 8002, 8090]

service_details = get_service_info(ip_address, open_ports)

for port, status in service_details.items():
    print(f"Port {port}: {status}")
