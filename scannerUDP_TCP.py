import socket
import threading
from queue import Queue


def tcp_scan(ip, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return True
    except (socket.timeout, ConnectionRefusedError):
        return False
    except socket.error as e:
        print(f"Ошибка при сканировании TCP порта {port}: {e}")
        return False
    finally:
        sock.close()


def udp_scan(ip, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b'', (ip, port))
        sock.recvfrom(1024)
        return True
    except socket.timeout:
        # Нет ответа - возможно порт открыт
        return True
    except ConnectionRefusedError:
        # Получен ICMP-ответ => "порт недоступен"
        return False
    except socket.error as e:
        print(f"Ошибка при сканировании UDP порта {port}: {e}\n")
        return False
    finally:
        sock.close()


def worker(ip, port_queue, results, scan_type, timeout):
    while not port_queue.empty():
        port = port_queue.get()
        if scan_type == 'tcp':
            if tcp_scan(ip, port, timeout):
                results.append(port)
        elif scan_type == 'udp':
            if udp_scan(ip, port, timeout):
                results.append(port)
        port_queue.task_done()


def scan_ports(ip, start_port, end_port, scan_type='tcp', threads=50, timeout=1):
    port_queue = Queue()
    results = []
    for port in range(start_port, end_port + 1):
        port_queue.put(port)
    for _ in range(threads):
        t = threading.Thread(
            target=worker,
            args=(ip, port_queue, results, scan_type, timeout)
        )
        t.daemon = True
        t.start()

    port_queue.join()
    return sorted(results)


if __name__ == "__main__":
    target_ip = input("Введите IP-адрес или домен: ")
    start_port = int(input("Начальный порт: "))
    end_port = int(input("Конечный порт: "))

    # Проверка DNS
    try:
        socket.gethostbyname(target_ip)
    except socket.gaierror:
        print(f"Ошибка: IP/домен {target_ip} не существует или не разрешается!")
        exit()

    print("\nСканируем TCP-порты...")
    tcp_ports = scan_ports(target_ip, start_port, end_port, 'tcp')
    print("\nСканируем UDP-порты...")
    udp_ports = scan_ports(target_ip, start_port, end_port, 'udp')

    print("\nРезультаты:")
    print(f"Открытые TCP-порты: {tcp_ports if tcp_ports else 'Нет'}")
    print(f"Открытые UDP-порты: {udp_ports if udp_ports else 'Нет'}")