from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
import subprocess, platform, re
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

#Aqui vai ser feita a validação da senha
import re

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    return True, ""


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# -------------------
# Flask-Login
# -------------------
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -------------------
# Flask-Mail
# -------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'networkdashboard.sentinel@gmail.com'
app.config['MAIL_PASSWORD'] = 'pebv pqjw xltj ucsf'  # App password
app.config['MAIL_DEFAULT_SENDER'] = ('SENTINEL', 'networkdashboard.sentinel@gmail.com')
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# -------------------
# Models
# -------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))
    is_verified = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class UserSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    notify_security = db.Column(db.Boolean, default=True)
    device_updates = db.Column(db.Boolean, default=True)
    email_reports = db.Column(db.Boolean, default=True)
    two_factor = db.Column(db.Boolean, default=False)
    scan_frequency = db.Column(db.String(50), default='Every 24 hours')
    scan_intensity = db.Column(db.String(20), default='Standard')
    animations = db.Column(db.Boolean, default=True)
    theme = db.Column(db.String(10), default='dark')

    def to_dict(self):
        return {
            'notify_security': bool(self.notify_security),
            'device_updates': bool(self.device_updates),
            'email_reports': bool(self.email_reports),
            'two_factor': bool(self.two_factor),
            'scan_frequency': self.scan_frequency,
            'scan_intensity': self.scan_intensity,
            'animations': bool(self.animations),
            'theme': self.theme or 'dark'
        }


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# -------------------
# Authentication routes
# -------------------
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        # --- Validação da senha ---
        valid, msg = validate_password(password)
        if not valid:
            flash(msg, 'error')
            return render_template('auth.html', name=name, email=email)

        # --- Verifica se o usuário já existe ---
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if existing_user.is_verified:
                flash('Email already registered', 'error')
                return render_template('auth.html')
            else:
                # Remove user não verificado para permitir novo registo
                db.session.delete(existing_user)
                db.session.commit()

        # --- Cria novo usuário ---
        user = User(name=name, email=email, is_verified=False)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # --- Envia email de verificação ---
        token = s.dumps(email, salt='email-verify')
        link = url_for('verify_email', token=token, _external=True)

        html_body = f"""
<center>
  <table width="100%" bgcolor="#f0f4f8" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding: 40px 10px;">
        <!-- Card -->
        <table width="100%" bgcolor="#ffffff" cellpadding="0" cellspacing="0" style="border-radius:16px; overflow:hidden; max-width:600px;">
          
          <!-- Top gradient accent -->
          <tr>
            <td height="8" style="background: linear-gradient(90deg, #4F46E5, #6366F1);"></td>
          </tr>
          
          <tr>
            <td align="center" style="padding:30px;">
              
              <!-- Rounded Logo -->
              <img src="https://1clunny.github.io/SENTINEL.png"
                   width="120"
                   style="display:block; max-width:100%; height:auto; margin-bottom:25px; border-radius:24px;"
                   alt="SENTINEL Logo" />
              
              <!-- Heading -->
              <h2 style="font-family: 'Segoe UI', Helvetica, Arial, sans-serif; font-size:26px; color:#1F2937; font-weight:700; margin:0 0 15px 0;">
                Welcome, {name}!
              </h2>
              
              <!-- Body text -->
              <p style="font-family: 'Verdana', Helvetica, Arial, sans-serif; font-size:17px; color:#4B5563; line-height:1.6; margin:0 0 30px 0;">
                Thank you for registering. To activate your account, please verify your email by clicking the button below. This link will expire in 1 minute.
              </p>
              
              <!-- Button -->
              <a href="{link}" 
                 style="display:inline-block; padding:14px 28px; background-color:#4F46E5; color:#ffffff; text-decoration:none; border-radius:8px; font-family:'Segoe UI', Helvetica, Arial, sans-serif; font-weight:700; font-size:16px; min-width:140px; text-align:center;">
                Verify Email
              </a>
              
              <!-- Divider -->
              <hr style="margin:30px 0; border:none; border-top:1px solid #E5E7EB; width:80%;" />
              
              <!-- Footer -->
              <p style="font-family: 'Verdana', Helvetica, Arial, sans-serif; font-size:12px; color:#9CA3AF; line-height:1.4; margin:0;">
                If you did not register for this account, you can safely ignore this email.
              </p>
              
            </td>
          </tr>
        </table>
        <!-- End card -->
      </td>
    </tr>
  </table>
</center>
"""


        msg = Message('Verify your email', recipients=[email], html=html_body)
        mail.send(msg)

        flash('Registration successful! Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))

    # GET request apenas mostra o formulário
    return render_template('auth.html')


@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-verify', max_age=60) #Demora 1 minuto para expirar e assim so usuários podem se registrar novamente.
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            db.session.commit()
            flash('Email verified successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'error')
            return redirect(url_for('register'))
    except:
        flash('Verification link expired or invalid. Please register again.', 'error')
        return redirect(url_for('register'))


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user:
            if not user.is_verified:
                flash('Email not verified. Please check your inbox.', 'error')
                return redirect(url_for('login'))

            if user.check_password(password):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password', 'error')
        else:
            flash('User not found', 'error')

    return render_template('auth.html')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# -------------------
# Settings API
# -------------------
@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def api_settings():
    settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    if request.method == 'GET':
        if not settings:
            settings = UserSettings(user_id=current_user.id)
            db.session.add(settings)
            db.session.commit()
        return jsonify(settings.to_dict())

    data = request.get_json() or {}
    if not settings:
        settings = UserSettings(user_id=current_user.id)
        db.session.add(settings)

    for key in ['notify_security','device_updates','email_reports','two_factor','scan_frequency','scan_intensity','animations','theme']:
        if key in data:
            setattr(settings, key, data[key] if isinstance(data[key], bool) else str(data[key]))

    db.session.commit()
    return jsonify({'status': 'ok', 'settings': settings.to_dict()})


@app.route('/api/reset_settings', methods=['POST'])
@login_required
def api_reset_settings():
    settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    if not settings:
        settings = UserSettings(user_id=current_user.id)
        db.session.add(settings)
    settings.notify_security = True
    settings.device_updates = True
    settings.email_reports = True
    settings.two_factor = False
    settings.scan_frequency = 'Every 24 hours'
    settings.scan_intensity = 'Standard'
    settings.animations = True
    settings.theme = 'dark'
    db.session.commit()
    return jsonify({'status': 'ok', 'settings': settings.to_dict()})

# -------------------
# Keep your dashboard, network, security, settings, and other APIs here as before
# -------------------
@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/network")
def network():
    return render_template("network.html")

@app.route("/networks")
def networks():
    return render_template("networks.html")

@app.route("/security")
@login_required
def security():
    return render_template("security.html")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

#Botão de ajuda / relatório de bugs
@app.route("/send_help", methods=["POST"])
def send_help():
    data = request.get_json() or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"status": "error", "msg": "No message provided."})

    try:
        msg = Message(
            subject="User Help / Bug Report",
            recipients=["networkdashboard.sentinel@gmail.com"],
            body=f"User sent the following message:\n\n{message}"
        )
        mail.send(msg)
        return jsonify({"status":"ok"})
    except Exception as e:
        print("Error sending help email:", e)
        return jsonify({"status":"error"})
    
@app.route('/send_help', methods=['POST'])
def send_help_route():
    data = request.get_json()
    message = data.get('message')

    if not message:
        return jsonify({'status': 'error', 'msg': 'No message provided'})

    # Corpo simples do email
    msg = Message(subject='Help Request from User',
                  recipients=['networkdashboard.sentinel@gmail.com'],
                  body=message)
    mail.send(msg)

    return jsonify({'status': 'ok'})

import subprocess, platform, re, json
from flask import jsonify

@app.route('/api/wifi_scan')
def wifi_scan():
    try:
        system = platform.system().lower()
        networks = []
        source = "netsh"

        if "windows" in system:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                encoding="utf-8", errors="ignore"
            )

            ssids = re.findall(r"SSID \d+ : (.+)", output)
            bssids = re.findall(r"BSSID \d+ : ([\w:]+)", output)
            signals = re.findall(r"Signal\s+:\s+(\d+)%", output)
            auths = re.findall(r"Authentication\s+:\s+(.+)", output)
            encryptions = re.findall(r"Encryption\s+:\s+(.+)", output)
            channels = re.findall(r"Channel\s+:\s+(\d+)", output)
            radios = re.findall(r"Radio type\s+:\s+(.+)", output)

            for i, ssid in enumerate(ssids):
                networks.append({
                    "ssid": ssid.strip(),
                    "bssid": bssids[i] if i < len(bssids) else "",
                    "signal": int(signals[i]) if i < len(signals) else 0,
                    "auth": auths[i] if i < len(auths) else "Unknown",
                    "encryption": encryptions[i] if i < len(encryptions) else "Unknown",
                    "channel": channels[i] if i < len(channels) else "-",
                    "radio": radios[i] if i < len(radios) else ""
                })

        elif "linux" in system:
            source = "nmcli"
            output = subprocess.check_output(
                ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi"],
                encoding="utf-8", errors="ignore"
            )
            for line in output.splitlines():
                if not line.strip():
                    continue
                parts = line.split(":")
                networks.append({
                    "ssid": parts[0] or "<hidden>",
                    "bssid": parts[1] if len(parts) > 1 else "",
                    "signal": int(parts[2]) if len(parts) > 2 else 0,
                    "channel": parts[3] if len(parts) > 3 else "-",
                    "auth": parts[4] if len(parts) > 4 else "Unknown"
                })

        else:
            # Fallback: fake data so UI still works
            source = "demo"
            networks = [
                {"ssid": "Example WiFi", "signal": 80, "auth": "WPA2-Personal", "channel": 6, "bssid": "AA:BB:CC:DD:EE:FF", "radio": "802.11n"},
                {"ssid": "OfficeNet", "signal": 65, "auth": "WPA3", "channel": 11, "bssid": "11:22:33:44:55:66", "radio": "802.11ac"}
            ]

        return jsonify({"source": source, "networks": networks})

    except Exception as e:
        return jsonify({"error": str(e)})

# -------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)
    