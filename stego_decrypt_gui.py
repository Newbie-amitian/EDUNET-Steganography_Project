#Libraries needed for the code to work
import sys
import hashlib
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA
from PIL import Image
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QApplication, QWidget, QLabel, QPushButton, QFileDialog, QVBoxLayout,
                             QLineEdit, QComboBox, QMessageBox)

# Helper functions required for code reusability
def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary_string):
    chars = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

# XOR Decryption for handling unicode
def xor_decrypt(ciphertext, password):
    encrypted_bytes = bytes.fromhex(ciphertext)
    password_bytes = password.encode('utf-8')
    decrypted_bytes = bytes([encrypted_bytes[i] ^ password_bytes[i % len(password_bytes)] for i in range(len(encrypted_bytes))])
    return decrypted_bytes.decode('utf-8')

# AES-GCM Decryption for tampering protection
def aes_decrypt(ciphertext, password):
    key = hashlib.sha256(password.encode()).digest()
    data = bytes.fromhex(ciphertext)
    nonce, tag, enc_data = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(enc_data, tag).decode()

# ChaCha20 Decryption for bit-by-bit decryption
def chacha20_decrypt(ciphertext, password):
    key = hashlib.sha256(password.encode()).digest()
    data = bytes.fromhex(ciphertext)
    nonce, encrypted_text = data[:12], data[12:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(encrypted_text).decode()

# AES + ECC Hybrid Decryption for achieving speed and security both
def ecc_decrypt(ciphertext, private_key_path):
    with open(private_key_path, 'rb') as file:
        private_key = RSA.import_key(file.read())
    data = bytes.fromhex(ciphertext)
    encrypted_aes_key, nonce, tag, encrypted_text = data[:256], data[256:272], data[272:288], data[288:]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher_aes.decrypt_and_verify(encrypted_text, tag).decode()

# For extracting hidden text from Image 
def extract_text(image_path):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = list(img.getdata())
    binary_message = ""

    # For extracting lsb from each color respectively
    for pixel in pixels:
        r, g, b = pixel
        binary_message += str(r & 1)
        binary_message += str(g & 1)
        binary_message += str(b & 1)

    binary_message = binary_message.rstrip('0')
    stop_marker = '1111111111111110'
    end_index = binary_message.find(stop_marker)
    
    if end_index == -1:
        raise ValueError("No hidden message found in the image.")

    binary_message = binary_message[:end_index]
    return ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))

# Start of the PyQt GUI coding
class DecryptionGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle("LSB Steganography Decryption")
        self.setGeometry(100, 100, 500, 400)
        self.layout = QVBoxLayout()

        self.image_label = QLabel("No Image Selected")
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.image_label)

        self.image_button = QPushButton("Select Image")
        self.image_button.clicked.connect(self.select_image)
        self.layout.addWidget(self.image_button)

        self.method_combo = QComboBox()
        self.method_combo.addItems(["XOR", "AES", "ChaCha20", "AES+ECC"])
        self.method_combo.currentTextChanged.connect(self.toggle_key_fields)
        self.layout.addWidget(self.method_combo)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.password_input)

        self.private_key_button = QPushButton("Select Private Key")
        self.private_key_button.clicked.connect(self.select_private_key)
        self.layout.addWidget(self.private_key_button)
        self.private_key_button.hide()

        self.decrypt_button = QPushButton("Decrypt Message")
        self.decrypt_button.clicked.connect(self.decrypt_message)
        self.layout.addWidget(self.decrypt_button)

        self.setLayout(self.layout)
    
    def select_image(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Images (*.png *.bmp)")
        if file_path:
            self.image_label.setPixmap(QPixmap(file_path).scaled(400, 400, Qt.AspectRatioMode.KeepAspectRatio))
            self.image_path = file_path
    
    def select_private_key(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "Select Private Key", "", "PEM Files (*.pem)")
        if key_path:
            try:
                with open(key_path, 'rb') as file:
                    key = RSA.import_key(file.read())
                if key.has_private():
                    self.private_key_path = key_path
                    self.private_key_button.setText("Private Key Selected")
                    self.private_key_button.setEnabled(False)
                else:
                    QMessageBox.warning(self, "Error", "Wrong key selected. Please select a private key.")
            except Exception:
                QMessageBox.warning(self, "Error", "Invalid key file selected. Please select a valid private key.")
    
    def toggle_key_fields(self):
        if self.method_combo.currentText() == "AES+ECC":
            self.private_key_button.show()
            self.password_input.hide()
        else:
            self.private_key_button.hide()
            self.password_input.show()
    
    def decrypt_message(self):
        if not hasattr(self, 'image_path'):
            QMessageBox.warning(self, "Error", "Please select an image.")
            return
        
        method = self.method_combo.currentText()
        password = self.password_input.text() if method != "AES+ECC" else None
        private_key_path = getattr(self, 'private_key_path', None) if method == "AES+ECC" else None
        
        try:
            extracted_message = extract_text(self.image_path)
            if method == "XOR":
                decrypted_message = xor_decrypt(extracted_message, password)
            elif method == "AES":
                decrypted_message = aes_decrypt(extracted_message, password)
            elif method == "ChaCha20":
                decrypted_message = chacha20_decrypt(extracted_message, password)
            elif method == "AES+ECC":
                if not private_key_path:
                    QMessageBox.warning(self, "Error", "Please select a private key.")
                    return
                decrypted_message = ecc_decrypt(extracted_message, private_key_path)
            else:
                raise ValueError("Invalid decryption method")
            
            QMessageBox.information(self, "Decryption Successful", f"Decrypted Message: {decrypted_message}")
            
            # For automatically closing the application after encryption.
            QApplication.quit()
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DecryptionGUI()
    window.show()
    sys.exit(app.exec())
