from scapy.all import *

# Función para extraer datos ICMP de un archivo .pcap utilizando Scapy
def extract_icmp_data_scapy(pcap_file):
    try:
        # Lee los paquetes del archivo .pcap
        packets = rdpcap(pcap_file)
        icmp_data = ""

        # Itera sobre cada paquete
        for packet in packets:
            # Verifica si el paquete contiene un segmento ICMP
            if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request
                # Verifica si el paquete ICMP tiene un payload
                if packet[ICMP].payload:
                    # Convierte el payload del paquete ICMP a cadena y lo agrega a icmp_data
                    icmp_data += packet[ICMP].payload.load.decode('utf-8', errors='ignore')  # Decodifica el payload

        return icmp_data

    except Exception as e:
        print(f"Error al extraer datos ICMP: {e}")
        return ""

# Función para descifrar un texto cifrado utilizando el cifrado César
def caesar_decrypt(ciphertext, shift):
    decrypted_text = ""
    # Itera sobre cada carácter del texto cifrado
    for char in ciphertext:
        # Verifica si el carácter es una letra
        if char.isalpha():
            # Establece el offset ASCII según si la letra es mayúscula o minúscula
            ascii_offset = 65 if char.isupper() else 97
            # Calcula el nuevo carácter después de aplicar el desplazamiento
            new_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            decrypted_text += new_char
        else:
            # Si el carácter no es una letra, se agrega tal cual
            decrypted_text += char
    return decrypted_text

# Función para probar todos los desplazamientos posibles para descifrar el texto
def try_all_shifts(ciphertext):
    possible_messages = []
    # Itera sobre todos los desplazamientos posibles (0-25)
    for shift in range(26):
        # Descifra el texto con el desplazamiento actual
        decrypted = caesar_decrypt(ciphertext, shift)
        # Agrega la tupla (shift, decrypted) a la lista de mensajes posibles
        possible_messages.append((shift, decrypted))
    return possible_messages

# Función para imprimir los mensajes posibles, destacando aquellos que contienen una palabra clave
def print_with_highlight(messages, keyword=None):
    # Itera sobre cada mensaje posible
    for shift, message in messages:
        # Verifica si la palabra clave está en el mensaje (ignorando mayúsculas/minúsculas)
        if keyword and keyword.lower() in message.lower():
            # Imprime el mensaje en verde si contiene la palabra clave
            print(f"\033[92mShift {shift}: {message}\033[0m")
        else:
            # Imprime el mensaje sin destacar si no contiene la palabra clave
            print(f"Shift {shift}: {message}")

# Bloque principal del script
if __name__ == "__main__":
    # Solicita al usuario la ruta al archivo .pcap
    pcap_file = input("Ingresa la ruta al archivo .pcap: ")
    # Extrae los datos cifrados del archivo .pcap
    ciphertext = extract_icmp_data_scapy(pcap_file)
    
    # Verifica si se extrajo algún texto cifrado
    if not ciphertext:
        print("No se pudo extraer ningún texto cifrado.")
    else:
        # Imprime el texto cifrado extraído
        print(f"Texto cifrado extraído: {ciphertext}")
        
        # Descifra el texto cifrado con todos los desplazamientos posibles
        all_shifts = try_all_shifts(ciphertext)
        
        # Solicita al usuario una palabra clave opcional para destacar
        keyword = input("Ingresa una palabra clave opcional para destacar (o presiona Enter para omitir): ")
        
        # Imprime los mensajes posibles, destacando aquellos que contienen la palabra clave
        print_with_highlight(all_shifts, keyword)