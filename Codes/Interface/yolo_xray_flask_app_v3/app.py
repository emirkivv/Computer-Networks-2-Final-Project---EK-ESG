from flask import Flask, render_template, request
import os
from detect import run_detection
from datetime import datetime

app = Flask(__name__)
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        image = request.files["xray"]
        if image:
            filename = datetime.now().strftime("%Y%m%d%H%M%S") + "_" + image.filename
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            image.save(filepath)

            # Tahmin çalıştır
            output_path = run_detection(filepath)

            return render_template("index.html", uploaded=True, output_image=output_path)

    return render_template("index.html", uploaded=False)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
