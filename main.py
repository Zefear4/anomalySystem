from scapy.all import *
import statistics
from collections import defaultdict
import joblib
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from sklearn.preprocessing import StandardScaler, LabelEncoder
import os
import logging
from datetime import datetime

# Настройки системы
INTERFACE = r'\Device\NPF_{E834C88A-01A5-485F-B061-200D93B6EBDF}'
MODEL_DIR = 'saved_model'
THRESHOLD = 0.95  # Порог для автоэнкодера

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    filename='anomaly_detection.log',
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'  # режим добавления в конец файла
)
logger = logging.getLogger(__name__)

# Уникальные значения признаков
PROTO_VALUES = ['3pc', 'a/n', 'aes-sp3-d', 'any', 'argus', 'aris', 'arp', 'ax.25', 'bbn-rcc', 'bna',
                'br-sat-mon', 'cbt', 'cftp', 'chaos', 'compaq-peer', 'cphb', 'cpnx', 'crtp', 'crudp',
                'dcn', 'ddp', 'ddx', 'dgp', 'egp', 'eigrp', 'emcon', 'encap', 'etherip', 'fc', 'fire',
                'ggp', 'gmtp', 'gre', 'hmp', 'i-nlsp', 'iatp', 'ib', 'icmp', 'idpr', 'idpr-cmtp', 'idrp',
                'ifmp', 'igmp', 'igp', 'il', 'ip', 'ipcomp', 'ipcv', 'ipip', 'iplt', 'ipnip', 'ippc',
                'ipv6', 'ipv6-frag', 'ipv6-no', 'ipv6-opts', 'ipv6-route', 'ipx-n-ip', 'irtp', 'isis',
                'iso-ip', 'iso-tp4', 'kryptolan', 'l2tp', 'larp', 'leaf-1', 'leaf-2', 'merit-inp',
                'mfe-nsp', 'mhrp', 'micp', 'mobile', 'mtp', 'mux', 'narp', 'netblt', 'nsfnet-igp', 'nvp',
                'ospf', 'pgm', 'pim', 'pipe', 'pnni', 'pri-enc', 'prm', 'ptp', 'pup', 'pvp', 'qnx', 'rdp',
                'rsvp', 'rtp', 'rvd', 'sat-expak', 'sat-mon', 'sccopmce', 'scps', 'sctp', 'sdrp',
                'secure-vmtp', 'sep', 'skip', 'sm', 'smp', 'snp', 'sprite-rpc', 'sps', 'srp', 'st2', 'stp',
                'sun-nd', 'swipe', 'tcf', 'tcp', 'tlsp', 'tp++', 'trunk-1', 'trunk-2', 'ttp', 'udp', 'unas',
                'uti', 'vines', 'visa', 'vmtp', 'vrrp', 'wb-expak', 'wb-mon', 'wsn', 'xnet', 'xns-idp',
                'xtp', 'zero']

SERVICE_VALUES = ['-', 'dhcp', 'dns', 'ftp', 'ftp-data', 'http', 'irc', 'pop3', 'radius', 'smtp', 'snmp', 'ssh', 'ssl']

STATE_VALUES = ['CON', 'ECO', 'FIN', 'INT', 'PAR', 'REQ', 'RST', 'URN', 'no']


# Загрузка моделей
def load_models():
    """Загружает модели и препроцессоры"""
    try:
        # Загружаем Random Forest
        rf_model = joblib.load(os.path.join(MODEL_DIR, 'rf_model.pkl'))

        # Загружаем автоэнкодер
        artifacts = joblib.load(os.path.join(MODEL_DIR, 'model_artifacts.joblib'))
        autoencoder = artifacts['autoencoder']
        scaler = artifacts['scaler']

        # Создаем LabelEncoder'ы с фиксированными классами
        proto_encoder = LabelEncoder().fit(PROTO_VALUES)
        service_encoder = LabelEncoder().fit(SERVICE_VALUES)
        state_encoder = LabelEncoder().fit(STATE_VALUES)

        encoders = {
            'proto': proto_encoder,
            'service': service_encoder,
            'state': state_encoder
        }

        return rf_model, autoencoder, scaler, encoders
    except Exception as e:
        logger.error(f"Ошибка загрузки моделей: {e}")
        raise


# Инициализация моделей
rf_model, autoencoder, scaler, encoders = load_models()


def new_connection():
    return {
        'start_time': None,
        'end_time': None,
        'proto': None,
        'service': None,
        'state': None,
        'spkts': 0,
        'dpkts': 0,
        'sbytes': 0,
        'dbytes': 0,
        'sttl': [],
        'dttl': [],
        'sload': 0,
        'dload': 0,
        'sinpkt': [],
        'dinpkt': [],
        'sjit': [],
        'djit': [],
        'swin': [],
        'dwin': [],
        'last_s_pkt_time': None,
        'last_d_pkt_time': None
    }


connection_stats = defaultdict(new_connection)


def get_service(port):
    """Определение сервиса по порту с учетом известных значений"""
    SERVICE_PORTS = {
        80: 'http', 443: 'ssl', 21: 'ftp', 22: 'ssh',
        25: 'smtp', 53: 'dns', 110: 'pop3', 143: 'irc',
        3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
        67: 'dhcp', 68: 'dhcp', 161: 'snmp', 162: 'snmp',
        1812: 'radius', 1813: 'radius'
    }
    service = SERVICE_PORTS.get(port, '-')
    return service if service in SERVICE_VALUES else '-'


def preprocess_features(stats):
    """Подготовка признаков для моделей с учетом фиксированных классов"""
    try:
        # Кодируем категориальные признаки
        encoded_proto = encoders['proto'].transform([stats['proto']])[0]
        encoded_service = encoders['service'].transform([stats['service']])[0]
        encoded_state = encoders['state'].transform([stats['state']])[0]

        features = [
            stats['dur'],
            encoded_proto,
            encoded_service,
            encoded_state,
            stats['spkts'],
            stats['dpkts'],
            stats['sbytes'],
            stats['dbytes'],
            stats['sttl'],
            stats['dttl'],
            stats['rate'],
            stats['sload'],
            stats['dload'],
            stats['sinpkt'],
            stats['dinpkt'],
            stats['sjit'],
            stats['djit'],
            stats['swin'],
            stats['dwin'],
            stats['ct_srv_src'],
            stats['ct_srv_dst']
        ]

        return scaler.transform([features])
    except Exception as e:
        logger.error(f"Ошибка предобработки признаков: {e}")
        return None


def analyze_with_rf(features):
    """Анализ с помощью Random Forest"""
    if features is None:
        return False
    return rf_model.predict(features)[0] == 1  # 1 = атака


def analyze_with_autoencoder(features):
    """Анализ с помощью автоэнкодера"""
    if features is None:
        return False
    reconstructed = autoencoder.predict(features, verbose=0)
    mse = np.mean(np.power(features - reconstructed, 2), axis=1)
    return mse > THRESHOLD


def log_anomaly(conn_id, stats, detector_type):
    """Логирование аномалии в файл"""
    src_ip, dst_ip, sport, dport, _ = conn_id

    # Формируем детализированное сообщение для лога
    log_message = (
        f"Обнаружена аномалия ({detector_type})\n"
        f"Соединение: {src_ip}:{sport} → {dst_ip}:{dport}\n"
        f"Протокол: {stats['proto']}, Сервис: {stats['service']}, Состояние: {stats['state']}\n"
        f"Длительность: {stats['dur']:.2f} сек\n"
        f"Пакеты: {stats['spkts']} исх. / {stats['dpkts']} вх.\n"
        f"Байты: {stats['sbytes']:,} исх. / {stats['dbytes']:,} вх.\n"
        f"Скорость: {stats['rate']:.2f} пак/сек\n"
        f"Нагрузка: {stats['sload']:.2f} / {stats['dload']:.2f} байт/сек\n"
        f"TTL: {stats['sttl']:.1f} исх. / {stats['dttl']:.1f} вх.\n"
        f"Интервал пакетов: {stats['sinpkt']:.5f} / {stats['dinpkt']:.5f} сек\n"
        f"Джиттер: {stats['sjit']:.5f} / {stats['djit']:.5f} сек\n"
        f"TCP-окно: {stats['swin']:.1f} / {stats['dwin']:.1f}\n"
        f"Соединений от источника: {stats['ct_srv_src']}\n"
        f"Соединений к назначению: {stats['ct_srv_dst']}\n"
        f"{'='*50}"
    )

    # Логируем аномалию
    logger.warning(log_message)

    # Вывод в консоль (сокращенная версия)
    print(f"\n[!] Обнаружена аномалия ({detector_type})")
    print(f"Соединение: {src_ip}:{sport} -> {dst_ip}:{dport}")
    print(f"Протокол: {stats['proto']}, Сервис: {stats['service']}")
    print(f"Пакеты: {stats['spkts']}/{stats['dpkts']}, Байты: {stats['sbytes']}/{stats['dbytes']}")


def process_connection(conn_id, stats):
    """Обработка завершенного соединения"""
    try:
        features = preprocess_features(stats)
        if features is None:
            return

        # Первый уровень: Random Forest
        if analyze_with_rf(features):
            log_anomaly(conn_id, stats, "Random Forest")
            return

        # Второй уровень: автоэнкодер
        if analyze_with_autoencoder(features):
            log_anomaly(conn_id, stats, "Autoencoder")

    except Exception as e:
        logger.error(f"Ошибка анализа соединения: {e}")


def process_packet(packet):
    try:
        if not IP in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        sport = dport = 0
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            proto_name = 'tcp'
            tcp_layer = packet[TCP]
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            proto_name = 'udp'
            tcp_layer = None
        else:
            proto_name = 'other'
            tcp_layer = None

        # Приводим протокол к известным значениям
        proto_name = proto_name if proto_name in PROTO_VALUES else 'tcp' if proto_name == 'tcp' else 'udp' if proto_name == 'udp' else 'other'

        conn_id = (src_ip, dst_ip, sport, dport, proto)
        reverse_conn_id = (dst_ip, src_ip, dport, sport, proto)

        if conn_id in connection_stats:
            direction = 'forward'
        elif reverse_conn_id in connection_stats:
            direction = 'reverse'
            conn_id = reverse_conn_id
        else:
            direction = 'forward'
            connection_stats[conn_id]['start_time'] = packet.time
            connection_stats[conn_id]['proto'] = proto_name
            connection_stats[conn_id]['service'] = get_service(dport)
            connection_stats[conn_id]['state'] = 'no'  # Начальное состояние

        stats = connection_stats[conn_id]
        stats['end_time'] = packet.time

        if direction == 'forward':
            stats['spkts'] += 1
            stats['sbytes'] += len(packet)
            if IP in packet:
                stats['sttl'].append(packet[IP].ttl)

            if TCP in packet:
                stats['swin'].append(tcp_layer.window)

                if tcp_layer.flags & 0x02:  # SYN
                    stats['state'] = 'REQ'
                elif tcp_layer.flags & 0x10:  # ACK
                    stats['state'] = 'CON' if stats['state'] != 'REQ' else 'ECO'
                elif tcp_layer.flags & 0x04:  # RST
                    stats['state'] = 'RST'
                elif tcp_layer.flags & 0x01:  # FIN
                    stats['state'] = 'FIN'

            if stats['last_s_pkt_time'] is not None:
                iat = packet.time - stats['last_s_pkt_time']
                stats['sinpkt'].append(iat)
                if len(stats['sinpkt']) > 1:
                    stats['sjit'].append(abs(iat - stats['sinpkt'][-2]))
            stats['last_s_pkt_time'] = packet.time

        else:
            stats['dpkts'] += 1
            stats['dbytes'] += len(packet)
            if IP in packet:
                stats['dttl'].append(packet[IP].ttl)

            if TCP in packet:
                stats['dwin'].append(tcp_layer.window)

            if stats['last_d_pkt_time'] is not None:
                iat = packet.time - stats['last_d_pkt_time']
                stats['dinpkt'].append(iat)
                if len(stats['dinpkt']) > 1:
                    stats['djit'].append(abs(iat - stats['dinpkt'][-2]))
            stats['last_d_pkt_time'] = packet.time

        # Проверка на завершение соединения
        if stats['state'] in ['FIN', 'RST'] or (stats['spkts'] + stats['dpkts']) >= 20:
            # Расчет дополнительных метрик
            duration = stats['end_time'] - stats['start_time']
            stats['dur'] = max(duration, 0.001)
            stats['rate'] = (stats['spkts'] + stats['dpkts']) / stats['dur']
            stats['sload'] = stats['sbytes'] / stats['dur']
            stats['dload'] = stats['dbytes'] / stats['dur']
            stats['sttl'] = statistics.mean(stats['sttl']) if stats['sttl'] else 0
            stats['dttl'] = statistics.mean(stats['dttl']) if stats['dttl'] else 0
            stats['swin'] = statistics.mean(stats['swin']) if stats['swin'] else 0
            stats['dwin'] = statistics.mean(stats['dwin']) if stats['dwin'] else 0
            stats['sinpkt'] = statistics.mean(stats['sinpkt']) if stats['sinpkt'] else 0
            stats['dinpkt'] = statistics.mean(stats['dinpkt']) if stats['dinpkt'] else 0
            stats['sjit'] = statistics.mean(stats['sjit']) if stats['sjit'] else 0
            stats['djit'] = statistics.mean(stats['djit']) if stats['djit'] else 0

            # Подсчет соединений
            stats['ct_srv_src'] = sum(1 for conn in connection_stats
                                    if conn[0] == src_ip and conn[3] == dport)
            stats['ct_srv_dst'] = sum(1 for conn in connection_stats
                                    if conn[1] == dst_ip and conn[2] == sport)

            # Анализ соединения
            process_connection(conn_id, stats)

            # Удаление завершенного соединения
            del connection_stats[conn_id]

    except Exception as e:
        logger.error(f"Ошибка обработки пакета: {e}")


def start_detection():
    print("Запуск гибридной системы обнаружения аномалий...")
    print(f"Интерфейс: {INTERFACE}")
    print(f"Логирование в файл: anomaly_detection.log")
    print("Нажмите Ctrl+C для остановки")

    logger.info("Система обнаружения аномалий запущена")

    try:
        sniff(iface=INTERFACE, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\nОстановка системы обнаружения")
        logger.info("Система обнаружения аномалий остановлена")
    except Exception as e:
        logger.error(f"Критическая ошибка: {str(e)}")
        raise


if __name__ == "__main__":
    start_detection()