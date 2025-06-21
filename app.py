from flask import Flask, request, render_template
import sys
from io import StringIO
from time import time

from xor import xor_encrypt
from tham_ma_xor import brute_xor
from aes import aes_encrypt
from tham_ma_aes import brute_aes

app = Flask(__name__)

def format_duration(seconds):
    if seconds < 60:
        return f"{seconds:.2f} giây"
    elif seconds < 3600:
        minutes = int(seconds) // 60
        secs = seconds % 60
        return f"{minutes} phút {secs:.2f} giây"
    else:
        hours = int(seconds) // 3600
        minutes = (int(seconds) % 3600) // 60
        secs = seconds % 60
        return f"{hours} giờ {minutes} phút {secs:.2f} giây"

def capture_brute(func, key_size, *args):
    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()
    start = time()
    tried_dict, valid_result = func(*args, key_size=key_size)
    duration = round(time() - start, 2)
    sys.stdout = old_stdout


    tried_keys = "\n".join(
        f"Thử key: {k} → {v}" for k, v in (list(tried_dict.items())[-2000:] if key_size == 3 else tried_dict.items())
    )

  
    result_lines = []

    
    if func.__name__ == "brute_xor":
        result_lines.append(f"Thám mã XOR {key_size * 8}-bit")
    elif func.__name__ == "brute_aes":
        result_lines.append(f"Thám mã AES {key_size * 8}-bit")
    else:
        result_lines.append("Thám mã không xác định")

    if valid_result:
        key, plaintext, count = valid_result
        result_lines.append(f"Key: {key}")
        result_lines.append(f"Plaintext: {plaintext}")
        result_lines.append(f"Số lần thực hiện: {count}")
    else:
        result_lines.append("Không tìm thấy khóa phù hợp.")

    result_lines.append(f"Thời gian xử lý: {format_duration(duration)}")

    return "\n".join(result_lines).strip(), tried_keys.strip()


@app.route("/", methods=["GET", "POST"])
def crypto_tool():
    enc_result = dec_result = error = tried_keys = None
    dec_mode = None  

    if request.method == "POST":
        action = request.form.get("action")
        enc_mode = request.form.get("enc_mode")
        dec_mode = request.form.get("dec_mode")
        enc_data = request.form.get("enc_data", "")
        dec_data = request.form.get("dec_data", "")
        enc_key = request.form.get("enc_key", "")

        try:
            # Mã hóa
            if enc_data and enc_key and enc_mode in {"xor_enc", "aes_enc"} and action == "Thực hiện mã hóa":
                if enc_mode == "xor_enc":
                    enc_result = xor_encrypt(enc_data, enc_key).hex()
                elif enc_mode == "aes_enc":
                    enc_result = aes_encrypt(enc_data, enc_key).hex()

            # Thám mã
            if action == "Thực hiện thám mã" and dec_data:
                if dec_mode == "xor_brute8":
                    dec_result, tried_keys = capture_brute(brute_xor, 1, dec_data)
                elif dec_mode == "xor_brute16":
                    dec_result, tried_keys = capture_brute(brute_xor, 2, dec_data)
                elif dec_mode == "xor_brute24":
                    dec_result, tried_keys = capture_brute(brute_xor, 3, dec_data)
                elif dec_mode == "aes_brute8":
                    dec_result, tried_keys = capture_brute(brute_aes, 1, dec_data)
                elif dec_mode == "aes_brute16":
                    dec_result, tried_keys = capture_brute(brute_aes, 2, dec_data)
                elif dec_mode == "aes_brute24":
                    dec_result, tried_keys = capture_brute(brute_aes, 3, dec_data)

        except Exception as e:
            error = str(e)

    return render_template(
        "index.html",
        enc_result=enc_result,
        dec_result=dec_result,
        tried_keys=tried_keys,
        error=error,
        dec_mode=dec_mode  # ✅ Luôn tồn tại, tránh UnboundLocalError
    )


if __name__ == "__main__":
    app.run(debug=True, port=5050)
