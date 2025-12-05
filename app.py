from flask import Flask
from flask_cors import CORS
from routes.image_routes import image_bp
from routes.url_routes import url_bp   # ⬅️ add this

app = Flask(__name__)

CORS(
    app,
    resources={r"/api/*": {"origins": "http://localhost:5173"}},
)

app.register_blueprint(image_bp)
app.register_blueprint(url_bp)        # ⬅️ register URL routes

@app.route("/")
def home():
    return "Flask backend is running on port 3000 ✅", 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=3000, debug=True)
