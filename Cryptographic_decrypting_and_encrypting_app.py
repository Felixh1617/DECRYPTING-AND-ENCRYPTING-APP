from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def generate_key_pair():
    """
    Generates an RSA key pair (public key and private key).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_text(text, public_key):
    """
    Encrypts the given text using RSA encryption with OAEP padding.
    Returns the encrypted ciphertext.
    """
    plaintext = text.encode('utf-8')
    cipher_text = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text

def decrypt_text(cipher_text, private_key):
    """
    Decrypts the given ciphertext using RSA decryption with OAEP padding.
    Returns the decrypted plaintext.
    """
    plain_text = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')
    return plain_text

if __name__ == "__main__":
    # Generate a key pair
    private_key, public_key = generate_key_pair()

    while True:
        print("\nChoose an option:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            # Encrypt
            original_text = input("Enter the text to encrypt: ")
            encrypted_text = encrypt_text(original_text, public_key)
            print("Encrypted Text:", encrypted_text.hex())

        elif choice == '2':
            # Decrypt
            encrypted_text = input("Enter the encrypted text (in hex format): ")
            try:
                encrypted_bytes = bytes.fromhex(encrypted_text)
                decrypted_text = decrypt_text(encrypted_bytes, private_key)
                print("Decrypted Text:", decrypted_text)
            except ValueError:
                print("Invalid hex format.")

        elif choice == '3':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
