import os
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for
from flask_socketio import SocketIO
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from scapy.all import sniff, get_if_list
from analysis import PacketAnalyzer
from intelligence import ThreatIntelligence
from config import Config
import logging
import ctypes
import pyshark

app = Flask(__name__)
app.config.from_object(Config)
Config.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

packet_analyzer = PacketAnalyzer(socketio)
threat_intel = ThreatIntelligence()
sniffing = False
sniff_thread = None

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    if username in Config.USERS:
        return User(username)
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            if not username or not password:
                return jsonify({'success': False, 'error': 'Username and password are required'})
            
            if username in Config.USERS and Config.USERS[username] == password:
                user = User(username)
                login_user(user)
                return jsonify({'success': True})
            else:
                return jsonify({'success': False, 'error': 'Invalid username or password'})
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            return jsonify({'success': False, 'error': 'An error occurred during login'})
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/start_capture', methods=['POST'])
@login_required
def start_capture():
    global sniffing, sniff_thread
    if sniffing:
        return jsonify({'success': False, 'error': 'Already capturing'})
    data = request.get_json()
    iface = data.get('interface')
    if not iface:
        return jsonify({'success': False, 'error': 'No interface specified'})
    sniffing = True
    sniff_thread = socketio.start_background_task(target=sniff_packets, iface=iface)
    return jsonify({'success': True})

@app.route('/api/stop_capture', methods=['POST'])
@login_required
def stop_capture():
    global sniffing
    sniffing = False
    return jsonify({'success': True})

@app.route('/api/interfaces')
@login_required
def list_interfaces():
    return jsonify({'interfaces': get_if_list()})

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

@app.route('/api/check_admin')
def check_admin():
    return jsonify({'is_admin': is_admin()})

def sniff_packets(iface):
    def packet_callback(packet):
        if sniffing:
            packet_analyzer.analyze_packet(packet)
    try:
        sniff(prn=packet_callback, store=0, iface=iface, filter=Config.DEFAULT_FILTER)
    except Exception as e:
        socketio.emit('error', {'message': str(e)})

def sniff_packets_pyshark(iface):
    capture = pyshark.LiveCapture(interface=iface)
    for packet in capture.sniff_continuously():
        if not sniffing:
            break
        # Convert packet to dict and emit via socketio
        src = getattr(packet, 'ip', None) and packet.ip.src or 'N/A'
        dst = getattr(packet, 'ip', None) and packet.ip.dst or 'N/A'
        proto = packet.highest_layer if hasattr(packet, 'highest_layer') else 'N/A'
        length = packet.length if hasattr(packet, 'length') else 'N/A'

        socketio.emit('packet', {
            'src': src,
            'dst': dst,
            'proto': proto,
            'length': length
        })

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format=Config.LOG_FORMAT)
    socketio.run(app, host='0.0.0.0', port=80, debug=True)
