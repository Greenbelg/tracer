import argparse
import time
from scapy.all import UDP, TCP, ICMP, IP, sr1
import ipwhois
import threading


class Answer: 
    def __init__(self, num, ip, time_in_ms):
        self.num = num
        self.ip = ip
        self.time_in_ms = time_in_ms
        self.asn = ''


def send_icmp_packet(dst, ttl, timeout):
    packet = IP(dst=dst, ttl=ttl) / ICMP()
    reply = sr1(packet, verbose=0, timeout=timeout)
    return reply


def send_tcp_packet(dst, ttl, port, timeout):
    packet = IP(dst=dst, ttl=ttl) / TCP(dport=port, flags="S")
    reply = sr1(packet, verbose=0, timeout=timeout)
    return reply


def send_udp_packet(dst, ttl, port, timeout):
    packet = IP(dst=dst, ttl=ttl) / UDP(dport=port)
    reply = sr1(packet, verbose=0, timeout=timeout)
    return reply


def traceroute(target, protocol, timeout, max_hops, port, verbose):
    answers = []
    ip = None
    ttl = 0
    max_hops = max_hops if max_hops else float('inf')
    
    while ttl < max_hops:
        ttl += 1
        if protocol == 'icmp':
            reply = send_icmp_packet(target, ttl, timeout)
        elif protocol == 'tcp':
            reply = send_tcp_packet(target, ttl, port, timeout)
        elif protocol == 'udp':
            reply = send_udp_packet(target, ttl, port, timeout)
        else:
            print("Неподдерживаемый протокол")
            return

        if reply:
            ip = reply.getlayer(IP).src
            time_in_ms = round((time.time() - reply.time) * 1000)
            answers.append(Answer(ttl, ip, time_in_ms))

        if ip == target:
            break
    
    threads = []
    for answer in answers:
        threads.append(threading.Thread(target=try_find_asn, args=(answer,), daemon=True))
        threads[-1].start()
    
    for thread in threads:
        thread.join()
    
    view_results(answers, verbose)

def view_results(answers: list[Answer], verbose):
    for answer in answers:
        if answer.ip == '*': 
            print(f'{answer.num} *') 
        else:   
            print(f'{answer.num} {answer.ip} {answer.time_in_ms}' if verbose == False  
                else f'{answer.num} {answer.ip} {answer.time_in_ms} {answer.asn}') 
 
def try_find_asn(answer: Answer):
    try:
        whois_answer = ipwhois.IPWhois(answer.ip).lookup_whois() 
        answer.asn = whois_answer['asn']
    except:
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("protocol", choices=['icmp', 'tcp', 'udp'])
    parser.add_argument("-t", "--timeout", type=int, default=2)
    parser.add_argument("-n", "--max-hops", type=int)
    parser.add_argument("-p", "--port", type=int)
    parser.add_argument("-v", "--verbose", action="store_true")
    
    args = parser.parse_args()

    if args.protocol in ['tcp', 'udp'] and not(args.port):
        print(f'Для {args.protocol} нужен порт')
        return
    
    if args.protocol == 'icmp' and args.port:
        print(f'Для {args.protocol} не нужен порт')
        return
    
    traceroute(args.target, args.protocol, args.timeout, args.max_hops, args.port, args.verbose)


if __name__ == "__main__":
    main()
