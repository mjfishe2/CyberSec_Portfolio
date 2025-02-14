import binascii
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

# Define the permutation choice 2 table
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 
       15, 6, 21, 10, 23, 19, 12, 4, 
       26, 8, 16, 7, 27, 20, 13, 2, 
       41, 52, 31, 37, 47, 55, 30, 40, 
       51, 45, 33, 48, 44, 49, 39, 56, 
       34, 53, 46, 42, 50, 36, 29, 32]

def permuted_choice_2(CD):
    """Perform the PC-2 permutation."""
    K = ''.join(CD[i - 1] for i in PC2)
    return K

def expand_to_56bit(key_bin):
    """Expand a 64-bit key into two 28-bit halves (C and D) for DES."""
    if len(key_bin) != 64:
        raise ValueError("Input key must be 64 bits.")
    C = key_bin[:28]
    D = key_bin[28:]
    return C, D

def reverse_key_schedule(k15, k16):
    """Reverse the key schedule to recover the original 64-bit DES key."""
    try:
        # Convert hex keys to binary
        k15_bytes = binascii.unhexlify(k15)
        k16_bytes = binascii.unhexlify(k16)

        if len(k15_bytes) != 8 or len(k16_bytes) != 8:
            raise ValueError("Key must be 64 bits (8 bytes).")

        k15_bin = ''.join(f'{byte:08b}' for byte in k15_bytes)
        k16_bin = ''.join(f'{byte:08b}' for byte in k16_bytes)

        # Ensure the keys are 64 bits
        if len(k15_bin) != 64 or len(k16_bin) != 64:
            raise ValueError("Input keys must be 64 bits.")

        # Expand to 56 bits
        C15, D15 = expand_to_56bit(k15_bin)
        C16, D16 = expand_to_56bit(k16_bin)

        # Recreate the original key using PC-2
        original_key = permuted_choice_2(C15 + D15)
        return binascii.unhexlify(f'{int(original_key, 2):016x}')  # Convert back to bytes

    except Exception as e:
        print(f"Error during key schedule reversal: {e}")
        return None

def des_decrypt(cipher_text, original_key):
    """Decrypt the cipher text using the DES algorithm."""
    try:
        cipher_bytes = binascii.unhexlify(cipher_text)

        print(f"Cipher bytes (length: {len(cipher_bytes)}): {cipher_bytes.hex()}")

        # Check if length is a multiple of block size
        if len(cipher_bytes) % 8 != 0:
            raise ValueError("Cipher text must be aligned to block boundary (8 bytes) in ECB mode.")

        des = DES.new(original_key, DES.MODE_ECB)

        decrypted_bytes = des.decrypt(cipher_bytes)

        print(f"Decrypted bytes (before unpadding): {decrypted_bytes.hex()}")

        # Check decrypted bytes length
        if len(decrypted_bytes) % DES.block_size != 0:
            raise ValueError("Decrypted bytes length is not aligned with block size.")

        # Unpad the decrypted bytes
        decrypted_text = unpad(decrypted_bytes, DES.block_size).decode('utf-8')
        return decrypted_text

    except ValueError as e:
        print(f"Error during decryption: {e}")
    except Exception as e:
        print(f"General error: {e}")
        return None

if __name__ == "__main__":
    k15 = "B9F4D1C6B74D3A1F"
    k16 = "8B1E4BAF3A1F3E2A"
    cipher_text = "39738581497f2c6b6e77f5ca632463d322c916b08612054b3c5c203320b583dbaa7c572f4d30977cbe5ddb9bf6096554dba1060606060606"

    # Reverse key schedule to get original key
    original_key = reverse_key_schedule(k15, k16)

    if original_key:
        print(f"Original DES key (64-bit, hex): {original_key.hex()}")

        # Decrypt the cipher text
        decrypted_text = des_decrypt(cipher_text, original_key)

        if decrypted_text:
            print(f"Decrypted text: {decrypted_text}")
        else:
            print("Decryption failed.")