from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/networks")
def networks():
    return render_template("networks.html")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
