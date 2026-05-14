# ==========================================
# DES Encryption/Decryption App với Gradio
# Chạy trên Google Colab
# ==========================================

# Cài thư viện (chạy ngoài file Python)
# pip install pycryptodome gradio

# ==========================================
# IMPORT
# ==========================================
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import gradio as gr
import os

# ==========================================
# HÀM XỬ LÝ KHÓA DES
# DES dùng khóa 8 bytes
# ==========================================
def format_key(key_text):
    key = key_text.encode("utf-8")

    # DES yêu cầu đúng 8 bytes
    if len(key) < 8:
        key = key.ljust(8, b'0')
    else:
        key = key[:8]

    return key


# ==========================================
# MÃ HÓA TEXT
# ==========================================
def encrypt_text(plain_text, key_text):
    try:
        key = format_key(key_text)

        cipher = DES.new(key, DES.MODE_CBC)

        padded_text = pad(plain_text.encode("utf-8"), DES.block_size)

        encrypted_bytes = cipher.encrypt(padded_text)

        # Ghép IV + ciphertext
        result = base64.b64encode(cipher.iv + encrypted_bytes).decode("utf-8")

        return result

    except Exception as e:
        return f"Lỗi: {str(e)}"


# ==========================================
# GIẢI MÃ TEXT
# ==========================================
def decrypt_text(cipher_text, key_text):
    try:
        key = format_key(key_text)

        data = base64.b64decode(cipher_text)

        iv = data[:8]
        encrypted_data = data[8:]

        cipher = DES.new(key, DES.MODE_CBC, iv)

        decrypted = unpad(
            cipher.decrypt(encrypted_data),
            DES.block_size
        )

        return decrypted.decode("utf-8")

    except Exception as e:
        return f"Lỗi: {str(e)}"


# ==========================================
# MÃ HÓA FILE
# ==========================================
def encrypt_file(file_obj, key_text):
    try:
        if file_obj is None:
            return "Chưa chọn file"

        key = format_key(key_text)

        input_path = file_obj.name

        with open(input_path, "rb") as f:
            file_data = f.read()

        cipher = DES.new(key, DES.MODE_CBC)

        encrypted_data = cipher.encrypt(
            pad(file_data, DES.block_size)
        )

        output_path = "encrypted.des"

        with open(output_path, "wb") as f:
            f.write(cipher.iv + encrypted_data)

        return output_path

    except Exception as e:
        return f"Lỗi: {str(e)}"


# ==========================================
# GIẢI MÃ FILE
# ==========================================
def decrypt_file(file_obj, key_text):
    try:
        if file_obj is None:
            return "Chưa chọn file"

        key = format_key(key_text)

        input_path = file_obj.name

        with open(input_path, "rb") as f:
            file_data = f.read()

        iv = file_data[:8]
        encrypted_data = file_data[8:]

        cipher = DES.new(key, DES.MODE_CBC, iv)

        decrypted_data = unpad(
            cipher.decrypt(encrypted_data),
            DES.block_size
        )

        output_path = "decrypted_output"

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        return output_path

    except Exception as e:
        return f"Lỗi: {str(e)}"


# ==========================================
# GIAO DIỆN GRADIO
# ==========================================
with gr.Blocks(title="DES Encryption App") as demo:

    gr.Markdown("# 🔐 DES Encryption & Decryption")

    # =========================
    # TAB TEXT
    # =========================
    with gr.Tab("Text Encryption"):

        gr.Markdown("## Mã hóa / Giải mã Text")

        txt_input = gr.Textbox(
            label="Nhập văn bản",
            lines=5
        )

        txt_key = gr.Textbox(
            label="Khóa DES (8 ký tự)",
            type="password"
        )

        with gr.Row():
            btn_encrypt_text = gr.Button("Mã hóa")
            btn_decrypt_text = gr.Button("Giải mã")

        txt_output = gr.Textbox(
            label="Kết quả",
            lines=5
        )

        btn_encrypt_text.click(
            encrypt_text,
            inputs=[txt_input, txt_key],
            outputs=txt_output
        )

        btn_decrypt_text.click(
            decrypt_text,
            inputs=[txt_input, txt_key],
            outputs=txt_output
        )

    # =========================
    # TAB FILE
    # =========================
    with gr.Tab("File Encryption"):

        gr.Markdown("## Mã hóa / Giải mã File")

        file_input = gr.File(
            label="Chọn file"
        )

        file_key = gr.Textbox(
            label="Khóa DES (8 ký tự)",
            type="password"
        )

        with gr.Row():
            btn_encrypt_file = gr.Button("Mã hóa File")
            btn_decrypt_file = gr.Button("Giải mã File")

        file_output = gr.File(
            label="Tải file kết quả"
        )

        btn_encrypt_file.click(
            encrypt_file,
            inputs=[file_input, file_key],
            outputs=file_output
        )

        btn_decrypt_file.click(
            decrypt_file,
            inputs=[file_input, file_key],
            outputs=file_output
        )

# ==========================================
# CHẠY APP
# ==========================================
demo.launch(share=True)