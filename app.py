from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
import subprocess
import platform
import re
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(100))

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

    if 'notify_security' in data:
        settings.notify_security = bool(data.get('notify_security'))
    if 'device_updates' in data:
        settings.device_updates = bool(data.get('device_updates'))
    if 'email_reports' in data:
        settings.email_reports = bool(data.get('email_reports'))
    if 'two_factor' in data:
        settings.two_factor = bool(data.get('two_factor'))
    if 'scan_frequency' in data:
        settings.scan_frequency = str(data.get('scan_frequency'))
    if 'scan_intensity' in data:
        settings.scan_intensity = str(data.get('scan_intensity'))
    if 'animations' in data:
        settings.animations = bool(data.get('animations'))
    if 'theme' in data:
        settings.theme = str(data.get('theme'))

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


@app.route('/api/delete_account', methods=['POST'])
@login_required
def api_delete_account():
    try:
        settings = UserSettings.query.filter_by(user_id=current_user.id).first()
        if settings:
            db.session.delete(settings)
        uid = current_user.id
        logout_user()
        user = User.query.get(uid)
        if user:
            db.session.delete(user)
        db.session.commit()
        return jsonify({'status': 'ok'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/change_password', methods=['POST'])
@login_required
def api_change_password():
    data = request.get_json() or {}
    new_password = data.get('new_password')
    if not new_password or len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    current_user.set_password(new_password)
    db.session.commit()
    return jsonify({'status': 'ok'})


def parse_netsh_output(output):
    networks = []
    ssid = None
    current = None
    bssid_index = None
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r'^SSID\s+\d+\s+:\s+(.*)$', line)
        if m:
            ssid = m.group(1).strip()
            current = {'ssid': ssid, 'bssids': [], 'auth': None, 'encryption': None}
            networks.append(current)
            bssid_index = 0
            continue
        if current is None:
            continue
        m = re.match(r'^Authentication\s+:\s+(.*)$', line)
        if m:
            current['auth'] = m.group(1).strip()
            continue
        m = re.match(r'^Encryption\s+:\s+(.*)$', line)
        if m:
            current['encryption'] = m.group(1).strip()
            continue
        m = re.match(r'^BSSID\s+\d+\s+:\s+(.*)$', line)
        if m:
            bssid = m.group(1).strip()
            current['bssids'].append({'bssid': bssid})
            bssid_index = len(current['bssids']) - 1
            continue
        m = re.match(r'^Signal\s+:\s+(\d+)%$', line)
        if m and current['bssids']:
            current['bssids'][bssid_index]['signal'] = int(m.group(1))
            continue
        m = re.match(r'^Channel\s+:\s+(\d+)', line)
        if m and current['bssids']:
            current['bssids'][bssid_index]['channel'] = int(m.group(1))
            continue
        m = re.match(r'^Radio type\s+:\s+(.*)$', line)
        if m and current['bssids']:
            current['bssids'][bssid_index]['radio'] = m.group(1).strip()
            continue

    flat = []
    for n in networks:
        for b in n.get('bssids', []) or [{'bssid': None, 'signal': None, 'channel': None, 'radio': None}]:
            flat.append({
                'ssid': n.get('ssid'),
                'bssid': b.get('bssid'),
                'signal': b.get('signal', 0),
                'channel': b.get('channel'),
                'radio': b.get('radio'),
                'auth': n.get('auth'),
                'encryption': n.get('encryption')
            })
    return flat


@app.route('/api/wifi_scan', methods=['GET'])
@login_required
def api_wifi_scan():
    system = platform.system()
    if system == 'Windows':
        try:
            cp = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], capture_output=True, text=True, timeout=8)
            out = cp.stdout or cp.stderr or ''
            results = parse_netsh_output(out)
            if not results and re.search(r'SSID|BSSID|Signal|Channel|Authentication|Encryption', out, re.I):
                print('netsh output (first 400 chars):', out[:400])
                ssids = []
                curr = None
                for line in out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    m = re.match(r'(?mi)^SSID\s*\d*\s*[:\-]\s*(.+)$', line)
                    if m:
                        curr = {'ssid': m.group(1).strip(), 'bssids': [], 'auth': None, 'encryption': None}
                        ssids.append(curr)
                        continue
                    if curr is None:
                        continue
                    m = re.match(r'(?mi)^BSSID\s*\d*\s*[:\-]\s*(.+)$', line)
                    if m:
                        curr['bssids'].append({'bssid': m.group(1).strip()})
                        continue
                    m = re.match(r'(?mi)^Signal\s*[:\-]\s*(\d+)%', line)
                    if m and curr.get('bssids'):
                        curr['bssids'][-1]['signal'] = int(m.group(1))
                        continue
                    m = re.match(r'(?mi)^Channel\s*[:\-]\s*(\d+)', line)
                    if m and curr.get('bssids'):
                        curr['bssids'][-1]['channel'] = int(m.group(1))
                        continue
                    m = re.match(r'(?mi)^Authentication\s*[:\-]\s*(.+)$', line)
                    if m:
                        curr['auth'] = m.group(1).strip()
                        continue
                    m = re.match(r'(?mi)^Encryption\s*[:\-]\s*(.+)$', line)
                    if m:
                        curr['encryption'] = m.group(1).strip()
                        continue

                fallback = []
                for n in ssids:
                    for b in n.get('bssids', []) or [{'bssid': None, 'signal': None, 'channel': None, 'radio': None}]:
                        fallback.append({
                            'ssid': n.get('ssid'),
                            'bssid': b.get('bssid'),
                            'signal': b.get('signal', 0),
                            'channel': b.get('channel'),
                            'radio': b.get('radio'),
                            'auth': n.get('auth'),
                            'encryption': n.get('encryption')
                        })
                if fallback:
                    print('netsh tolerant parse produced', len(fallback), 'entries')
                    return jsonify({'source': 'netsh', 'networks': fallback})

            return jsonify({'source': 'netsh', 'networks': results})
        except Exception as e:
            print('netsh scan failed:', e)

    demo = [
        {'ssid': 'Home-WiFi', 'bssid': 'AA:BB:CC:DD:EE:01', 'signal': 88, 'channel': 6, 'radio': '802.11n', 'auth': 'WPA2-Personal', 'encryption': 'AES'},
        {'ssid': 'Office-Guest', 'bssid': 'AA:BB:CC:DD:EE:02', 'signal': 64, 'channel': 11, 'radio': '802.11ac', 'auth': 'WPA2-Enterprise', 'encryption': 'AES'},
        {'ssid': 'Coffee_Shop', 'bssid': 'AA:BB:CC:DD:EE:03', 'signal': 42, 'channel': 1, 'radio': '802.11g', 'auth': 'Open', 'encryption': 'None'},
        {'ssid': 'HiddenNet', 'bssid': 'AA:BB:CC:DD:EE:04', 'signal': 12, 'channel': 36, 'radio': '802.11ac', 'auth': 'WPA3', 'encryption': 'GCMP'},
    ]
    return jsonify({'source': 'demo', 'networks': demo})

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('auth.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('auth.html')
        
        user = User(name=name, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)
