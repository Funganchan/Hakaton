def get_open_ports(host_info):
    return [port for port in host_info.all_ports() if host_info[port]['state'] == 'open']
