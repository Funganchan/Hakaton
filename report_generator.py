def generate_report(scan_results):
    with open('scan_report.txt', 'w') as report:
        for host, details in scan_results.items():
            report.write(f'Host: {host}, State: {details["state"]}, Open Ports: {details["open_ports"]}\n')