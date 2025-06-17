from flask import Flask, request, render_template
import sys
from io import StringIO
from time import time

from xor import xor_encrypt
from tham_ma_xor import brute_8bit as xor_brute_8bit_func, brute_16bit as xor_brute_16bit_func, brute_24bit as xor_brute_24bit_func
from aes import aes_encrypt
from tham_ma_aes import brute_8bit as aes_brute_8bit_func, brute_16bit as aes_brute_16bit_func, brute_24bit as aes_brute_24bit_func

app = Flask(__name__)

def capture_brute(func, *args):
    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()
    start = time()
    func(*args)
    duration = round(time() - start, 2)
    sys.stdout = old_stdout
    return mystdout.getvalue().rstrip() + f"\nThời gian xử lý: {duration} giây"


@app.route("/", methods=["GET", "POST"])
def crypto_tool():
    enc_result = dec_result = error = None

    if request.method == "POST":
        action = request.form.get("action")
        enc_mode = request.form.get("enc_mode")
        dec_mode = request.form.get("dec_mode")
        enc_data = request.form.get("enc_data", "")
        dec_data = request.form.get("dec_data", "")
        enc_key = request.form.get("enc_key", "")

        try:
            if enc_data and enc_key and enc_mode in {"xor_enc", "aes_enc"} and action == "Thực hiện mã hóa":
                if enc_mode == "xor_enc":
                    enc_result = xor_encrypt(enc_data, enc_key).hex()
                elif enc_mode == "aes_enc":
                    enc_result = aes_encrypt(enc_data, enc_key).hex()

            if action == "Thực hiện thám mã" and dec_data:
                if dec_mode == "xor_brute8":
                    dec_result = capture_brute(xor_brute_8bit_func, dec_data)
                elif dec_mode == "xor_brute16":
                    dec_result = capture_brute(xor_brute_16bit_func, dec_data)
                elif dec_mode == "xor_brute24":
                    dec_result = capture_brute(xor_brute_24bit_func, dec_data)
                elif dec_mode == "aes_brute8":
                    dec_result = capture_brute(aes_brute_8bit_func, dec_data)
                elif dec_mode == "aes_brute16":
                    dec_result = capture_brute(aes_brute_16bit_func, dec_data)
                elif dec_mode == "aes_brute24":
                    dec_result = capture_brute(aes_brute_24bit_func, dec_data)

        except Exception as e:
            error = str(e)

    return render_template("index.html", enc_result=enc_result, dec_result=dec_result, error=error)

if __name__ == "__main__":
    app.run(debug=True, port=5050)
