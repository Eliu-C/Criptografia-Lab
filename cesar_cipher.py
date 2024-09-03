def cesar_cipher(text, shift):
    # Inicializar el resultado
    result = ""

    # Recorrer cada carácter del texto
    for char in text:
        # Comprobar si el carácter es una letra
        if char.isalpha():
            # Convertir a mayúscula para manejar el cifrado
            ascii_offset = 65 if char.isupper() else 97
            # Aplicar el desplazamiento y ajustar alfabeto circular
            new_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            result += new_char
        else:
            # Si no es una letra, añadir el carácter sin cambios
            result += char

    return result

# Solicitar el texto y el desplazamiento al usuario
if __name__ == "__main__":
    text = input("Ingresa el texto a cifrar: ")
    shift = int(input("Ingresa el desplazamiento: "))
    encrypted_text = cesar_cipher(text, shift)
    print(f"Texto cifrado: {encrypted_text}")