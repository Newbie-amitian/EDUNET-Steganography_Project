#Libraries needed for the code to work
import sys
import hashlib
from PIL import Image
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from PyQt6.QtWidgets import (QApplication, QWidget, QLabel, QPushButton, QFileDialog, QVBoxLayout,
                             QLineEdit, QComboBox, QMessageBox)
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt

# Helper functions required for code reusability
def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary_string):
    chars = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

# XOR Encryption for handling unicode
def xor_encrypt(text, password):
    text_bytes = text.encode('utf-8')
    password_bytes = password.encode('utf-8')
    encrypted_bytes = bytes([text_bytes[i] ^ password_bytes[i % len(password_bytes)] for i in range(len(text_bytes))])
    return encrypted_bytes.hex()

# AES-GCM Encryption for tampering protection
def aes_encrypt(text, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return (cipher.nonce + tag + ciphertext).hex()

# ChaCha20 Encryption for bit-by-bit encryption
def chacha20_encrypt(text, password):
    key = hashlib.sha256(password.encode()).digest()
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    encrypted_text = cipher.encrypt(text.encode())
    return (nonce + encrypted_text).hex()

# AES + ECC Hybrid Encryption for achieving speed and security both
def ecc_encrypt(text, public_key_path):
    with open(public_key_path, 'rb') as file:
        public_key = RSA.import_key(file.read())
    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(text.encode())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return (encrypted_aes_key + cipher_aes.nonce + tag + ciphertext).hex()

# For hiding text from Image
def hide_text(image_path, output_path, secret_message, password, method, public_key_path=None):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    if method == "XOR":
        encrypted_message = xor_encrypt(secret_message, password)
    elif method == "AES":
        encrypted_message = aes_encrypt(secret_message, password)
    elif method == "ChaCha20":
        encrypted_message = chacha20_encrypt(secret_message, password)
    elif method == "AES+ECC":
        encrypted_message = ecc_encrypt(secret_message, public_key_path)
    else:
        raise ValueError("Invalid encryption method")

    binary_message = text_to_binary(encrypted_message) + '1111111111111110'
    pixels = list(img.getdata())
    new_pixels = []
    binary_index = 0

    for pixel in pixels:
        # For extracting the rbg components respectively
        r, g, b = pixel 

        '''Modifying lsb of each color channel for embedding bits of binary message
        respectively'''
        if binary_index < len(binary_message):
            r = (r & ~1) | int(binary_message[binary_index])
            binary_index += 1
        if binary_index < len(binary_message):
            g = (g & ~1) | int(binary_message[binary_index])
            binary_index += 1
        if binary_index < len(binary_message):
            b = (b & ~1) | int(binary_message[binary_index])
            binary_index += 1
        new_pixels.append((r, g, b))
    
    img.putdata(new_pixels)
    img.save(output_path)

# Start of the PyQt GUI coding
class SteganographyGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.image_path = None
        self.public_key_path = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle("LSB Steganography with Encryption")
        self.setGeometry(100, 100, 500, 500)

        self.layout = QVBoxLayout()

        self.image_label = QLabel("No Image Selected")
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.image_label)

        self.image_button = QPushButton("Select Image")
        self.image_button.clicked.connect(self.select_image)
        self.layout.addWidget(self.image_button)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Enter secret message")
        self.layout.addWidget(self.message_input)

        self.method_combo = QComboBox()
        self.method_combo.addItems(["XOR", "AES", "ChaCha20", "AES+ECC"])
        self.method_combo.currentTextChanged.connect(self.toggle_key_fields)
        self.layout.addWidget(self.method_combo)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.password_input)

        self.public_key_button = QPushButton("Select Public Key")
        self.public_key_button.clicked.connect(self.select_public_key)
        self.layout.addWidget(self.public_key_button)
        self.public_key_button.hide()

        self.generate_key_button = QPushButton("Generate RSA Keys")
        self.generate_key_button.clicked.connect(self.generate_rsa_keys)
        self.layout.addWidget(self.generate_key_button)
        self.generate_key_button.hide()

        self.save_button = QPushButton("Encrypt Message")
        self.save_button.clicked.connect(self.encrypt_and_hide_text)
        self.layout.addWidget(self.save_button)

        self.setLayout(self.layout)

    def select_image(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Images (*.png *.bmp *.jpg)")
        if file_path:
            self.image_path = file_path
            pixmap = QPixmap(file_path)
            self.image_label.setPixmap(pixmap.scaled(400, 400, Qt.AspectRatioMode.KeepAspectRatio))

    def select_public_key(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "Select Public Key", "", "PEM Files (*.pem)")
        if key_path:
            try:
                with open(key_path, "rb") as key_file:
                    key_data = key_file.read()
                
                    # Check if it's a valid public key
                    if key_data.startswith(b"-----BEGIN PUBLIC KEY-----"):
                        self.public_key_path = key_path
                        self.public_key_button.setText("Public Key Selected")
                        self.public_key_button.setEnabled(False)  # Grey out the button
                    else:
                        QMessageBox.warning(self, "Invalid Key", "Wrong key selected! Please select a Public Key.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to read key file: {str(e)}")


    def toggle_key_fields(self):
        if self.method_combo.currentText() == "AES+ECC":
            self.public_key_button.show()
            self.generate_key_button.show()
            self.password_input.hide()
        else:
            self.public_key_button.hide()
            self.generate_key_button.hide()
            self.password_input.show()

    # Function for generating rsa keys
    def generate_rsa_keys(self):
        private_key_path, _ = QFileDialog.getSaveFileName(self, "Save Private Key", "", "PEM Files (*.pem)")
        public_key_path, _ = QFileDialog.getSaveFileName(self, "Save Public Key", "", "PEM Files (*.pem)")

        if private_key_path and public_key_path:
            key = RSA.generate(2048)
            with open(private_key_path, "wb") as priv_file:
                priv_file.write(key.export_key())
            with open(public_key_path, "wb") as pub_file:
                pub_file.write(key.publickey().export_key())

            QMessageBox.information(self, "Success", f"RSA keys saved:\nPrivate: {private_key_path}\nPublic: {public_key_path}")
            self.public_key_path = public_key_path

    def encrypt_and_hide_text(self):
        if not self.image_path:
            QMessageBox.warning(self, "Error", "Please select an image.")
            return

        message = self.message_input.text()
        method = self.method_combo.currentText()
        password = self.password_input.text() if method != "AES+ECC" else None

        output_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted Image", "", "Images (*.png)")
        if output_path:
            hide_text(self.image_path, output_path, message, password, method, self.public_key_path)
            QMessageBox.information(self,"Success",f"Message Hidden Sucessfully.")

            # For automatically closing the application after encryption.
            QApplication.quit()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SteganographyGUI()
    window.show()
    sys.exit(app.exec())
