from scapy.all import *
import sys
import time

def send_stealth_ping(target_ip, encrypted_message):
    sequence_number = 1
    
    for char in encrypted_message:
        # Crear un paquete ICMP request con el carácter en el campo de datos
        icmp_packet = IP(dst=target_ip)/ICMP(seq=sequence_number)/Raw(load=char.encode('utf-8'))
        
        # Enviar el paquete
        send(icmp_packet)
        
        # Incrementar la secuencia para mantener coherencia
        sequence_number += 1
        
        # Pausar brevemente para simular un ping normal
        time.sleep(1)
    
    # Añadir la 'b' como último carácter para cumplir con el requisito
    final_packet = IP(dst=target_ip)/ICMP(seq=sequence_number)/Raw(load='b'.encode('utf-8'))
    send(final_packet)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python stealth_ping.py <IP_DESTINO> <MENSAJE_CIFRADO>")
        sys.exit(1)

    target_ip = sys.argv[1]
    encrypted_message = sys.argv[2]

    send_stealth_ping(target_ip, encrypted_message)