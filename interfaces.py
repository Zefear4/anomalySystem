from scapy.all import get_if_list, get_if_addr, get_if_hwaddr, get_if_raw_addr
import socket


def get_interfaces_info():
    """Получает список всех сетевых интерфейсов с их IP и MAC адресами"""
    interfaces = get_if_list()
    interfaces_info = []

    for interface in interfaces:
        try:
            # Получаем IPv4 адрес
            ip = get_if_addr(interface)
            if ip == '0.0.0.0':
                continue  # Пропускаем интерфейсы без IP

            # Получаем MAC адрес
            mac = get_if_hwaddr(interface)


            interfaces_info.append({
                'Interface': interface,
                'IP Address': ip,
                'MAC Address': mac,
            })
        except Exception as e:
            print(f"Ошибка при получении информации для интерфейса {interface}: {e}")

    return interfaces_info


def print_interfaces_info():
    """Выводит информацию о интерфейсах в удобном формате"""
    info = get_interfaces_info()

    if not info:
        print("Не найдено активных сетевых интерфейсов с IP-адресами")
        return

    print("\nДоступные сетевые интерфейсы:")
    print("-" * 70)
    print(f"{'Интерфейс':<15} {'IP-адрес':<20} {'MAC-адрес':<20} {'Маска подсети':<15}")
    print("-" * 70)

    for iface in info:
        print(f"{iface['Interface']:<15} {iface['IP Address']:<20} {iface['MAC Address']:<20}")


if __name__ == "__main__":
    print_interfaces_info()