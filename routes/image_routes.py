import os
import io
import gzip
from flask import Blueprint, request, jsonify
from PIL import Image

# Create a Blueprint for image-related routes
image_bp = Blueprint("image_bp", __name__)

# ----------------- Image Similarity Functions -----------------

def preprocess_image(path, size=(256, 256)):
    img = Image.open(path).convert('L').resize(size)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()

def compress(data):
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode='wb') as f:
        f.write(data)
    return len(out.getvalue())

def ncd(x_bytes, y_bytes):
    Cx = compress(x_bytes)
    Cy = compress(y_bytes)
    Cxy = compress(x_bytes + y_bytes)
    return (Cxy - min(Cx, Cy)) / max(Cx, Cy)

def find_closest_match(input_bytes, folder, size=(256, 256)):
    best_file = None
    best_ncd = float("inf")
    for filename in os.listdir(folder):
        if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
            img_path = os.path.join(folder, filename)
            try:
                img_bytes = preprocess_image(img_path, size)
                dist = ncd(input_bytes, img_bytes)
                if dist < best_ncd:
                    best_ncd = dist
                    best_file = filename
            except Exception as e:
                print("Error processing", img_path, e)
                continue
    return best_file, best_ncd

def classify_image(input_path, legit_folder, phished_folder):
    input_bytes = preprocess_image(input_path)

    best_legit_file, best_legit_ncd = find_closest_match(input_bytes, legit_folder)
    best_phish_file, best_phish_ncd = find_closest_match(input_bytes, phished_folder)

    results = {
        "best_legit_file": best_legit_file,
        "best_legit_ncd": best_legit_ncd,
        "best_phish_file": best_phish_file,
        "best_phish_ncd": best_phish_ncd,
    }

    if best_legit_ncd < best_phish_ncd:
        results["decision"] = "LEGITIMATE"
        results["message"] = f"✅ Classified as LEGITIMATE (lowest NCD = {best_legit_ncd:.4f})"
    else:
        results["decision"] = "PHISHED"
        results["message"] = f"⚠️ Classified as PHISHED (lowest NCD = {best_phish_ncd:.4f})"

    return results

# ----------------- Route: /api/image -----------------

@image_bp.route("/api/image", methods=["POST"])
def classify_image_route():
    """
    Called at POST http://localhost:3000/api/image
    with form-data: input_image = <file>
    """
    try:
        if "input_image" not in request.files:
            return jsonify({"error": "No file field 'input_image' in request"}), 400

        file = request.files["input_image"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        os.makedirs("uploads", exist_ok=True)
        input_path = os.path.join("uploads", file.filename)
        file.save(input_path)

        legit_folder = "./legit"
        phished_folder = "./phished"

        if not os.path.isdir(legit_folder) or not os.path.isdir(phished_folder):
            return jsonify({"error": "legit/ or phished/ folder not found on server"}), 500

        results = classify_image(input_path, legit_folder, phished_folder)

        return jsonify(results), 200

    except Exception as e:
        print("Server error:", e)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500
