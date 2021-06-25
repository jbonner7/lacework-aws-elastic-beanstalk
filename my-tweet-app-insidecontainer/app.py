from flask import Flask, render_template
import random
import platform

app = Flask(__name__)

# list of cat images
images = [
    "https://media.giphy.com/media/F3O8iAVrKgiR6QtgnE/giphy.gif",
    "https://media.giphy.com/media/A7ZbCuv0fJ0POGucwV/giphy.gif",
    "https://media.giphy.com/media/dOJt6XZlQw8qQ/giphy.gif",
    "https://media.giphy.com/media/gVBDitqGpVvRC/giphy.gif"
]

@app.route('/')
def index():
    url = random.choice(images)
    hostname = platform.node()
    return render_template('index.html', url=url, hostname=hostname)

if __name__ == "__main__":
    app.run(host="0.0.0.0")
