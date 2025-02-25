# Summary of Secure Data Hiding in Images Using Steganography

## encryption.py
- Handles the encryption process for hiding data within images.
- Provides options to encrypt secret messages using different encryption techniques.
- Supports XOR, AES, ChaCha20, and AES+ECC encryption methods.
- Implements a GUI to allow users to select encryption type, enter a password, and choose an image.
- Offers an option to save the encrypted image for later decryption.

## decryption.py
- Handles the decryption process to extract hidden data from images.
- Provides a GUI for users to input passwords or select decryption keys as needed.
- Supports the same encryption techniques used during encryption (XOR, AES, ChaCha20, AES+ECC).
- Displays extracted text messages or saves the retrieved file for access.

