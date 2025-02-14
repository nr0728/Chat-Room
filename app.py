from flask import Flask, render_template, request, jsonify, session
import requests
import string
import json
from datetime import datetime
import bleach
import hashlib
import random
from PIL import Image, ImageDraw, ImageFont
import io
import base64
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # 用于会话管理
socketio = SocketIO(app)

# 存储聊天记录的 JSON 文件路径
CHAT_HISTORY_FILE = 'chat_history.json'
chat_history = []

# 存储用户信息的 JSON 文件路径
USER_DATA_FILE = 'password.json'
users = {}

# 封禁的 IP 列表
BANNED_IP = ['211.158.25.248', '122.224.219.246']

# 允许的 HTML 标签和属性白名单
allowed_tags = ['p', 'br']
allowed_attrs = {'*': ['style'], 'p': ['style']}

def load_history():
	global chat_history
	try:
		with open(CHAT_HISTORY_FILE, 'r') as jFile:
			chat_history = json.load(jFile)
	except FileNotFoundError:
		chat_history = []

def load_users():
	global users
	try:
		with open(USER_DATA_FILE, 'r') as file:
			users = json.load(file)
	except FileNotFoundError:
		users = {}

def save_users():
	with open(USER_DATA_FILE, 'w') as file:
		json.dump(users, file)

characters = "wertyupadfghjkxcvbnm34578"

def selectedCharacters(length):
	return ''.join(random.choice(characters) for _ in range(length))

def getColor():
	return (random.randint(0, 66), random.randint(0, 66), random.randint(0, 66))

def getColor2():
	return (random.randint(233, 250), random.randint(233, 250), random.randint(233, 250))

def generate_captcha_image(size=(120, 60), characterNumber=5, bgcolor=getColor2()):
	imageTemp = Image.new('RGB', size, bgcolor)
	font = ImageFont.truetype('arial.ttf', 25)
	draw = ImageDraw.Draw(imageTemp)
	text = selectedCharacters(characterNumber)
	width, height = draw.textsize(text, font)
	offset = 2
	for i in range(characterNumber):
		offset += width // characterNumber
		position = (offset, (size[1] - height) // 2 + random.randint(-10, 10))
		draw.text(xy=position, text=text[i], font=font, fill=getColor())

	imageFinal = Image.new('RGB', size, bgcolor)
	pixelsFinal = imageFinal.load()
	pixelsTemp = imageTemp.load()
	for y in range(size[1]):
		offset = random.randint(-1, 1)
		for x in range(size[0]):
			newx = x + offset
			newx = max(0, min(newx, size[0] - 1))
			pixelsFinal[newx, y] = pixelsTemp[x, y]
	draw = ImageDraw.Draw(imageFinal)
	for i in range(int(size[0] * size[1] * 0.03)):
		draw.point((random.randint(0, size[0]), random.randint(0, size[1])), fill=getColor())
	for i in range(3):
		start = (0, random.randint(0, size[1] - 1))
		end = (size[0], random.randint(0, size[1] - 1))
		draw.line([start, end], fill=getColor(), width=1)
	for i in range(3):
		start = (-50, 50)
		end = (size[0] + 10, random.randint(0, size[1] + 10))
		draw.arc(start + end, 0, 360, fill=getColor())

	buf = io.BytesIO()
	imageFinal.save(buf, format='PNG')
	buf.seek(0)
	return (buf, text)


@app.route('/')
def index():
	return render_template('index.html')

@app.route('/user_status', methods=['POST'])
def user_status():
	print("fetching user status")
	username = session.get('username')
	print("fetching user status: get")
	if not username:
		return jsonify({'status': 'FAIL', 'message': 'login required'})
	if username == 'nr0728':
		username = '<strong><font color="#e74c3c" size="4">nr0728 </font><button style="border-radius:25px;background-color:#e74c3c;" class="admin"><font color="white" size="2">管理员</font></button></strong>'
	return jsonify({'status': 'OK', 'message': username})

@app.route('/send_message', methods=['POST'])
def send_message():
	if 'username' not in session:
		return jsonify({'status': 'FAIL', 'message': '需要登录'})

	username = session['username']
	message = request.form['message']

	if username not in users:
		return jsonify({'status': 'FAIL', 'message': '用户不存在'})

	cleaned_message = message
	if len(cleaned_message) > 100 and username != 'nr0728':
		return jsonify({'status': 'FAIL', 'message': '消息长度需小于 100 字符'})
	if username != 'nr0728':
		cleaned_message = bleach.clean(message, tags=allowed_tags, attributes=allowed_attrs)
		if '\u06ed' in cleaned_message or '\u0e49' in cleaned_message or '\u0e47' in cleaned_message:
			return jsonify({'status': 'FAIL', 'message': '非法字符'})

	now = datetime.now()
	timestamp = f"发送时间：{now.strftime('%Y-%m-%d %H:%M:%S')}.{now.strftime('%f')[:3]}.{now.strftime('%f')[3:]}"
	check_timestamp = datetime.now().timestamp()
	if not 'time' in session:
		session['time'] = 0
	if username != 'nr0728' and check_timestamp - session['time'] < 5:
		return jsonify({'status': 'FAIL', 'message': '发送消息的频率太快，请稍后再试'})
	session['time'] = check_timestamp
	user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
#	user_ip = request.remote_addr
	print(user_ip)
	try:
		user_ip = user_ip.split(',')[0].strip()
	except:
		pass
	if user_ip in BANNED_IP:
		return jsonify({'status': 'FAIL', 'message': 'IP 已封禁，请联系 monkey@llong.tech'})
	response = requests.get(f'https://ipinfo.io/{user_ip}/json')
	location_data = response.json()
	city = location_data.get('city', 'Unknown City')
	region = location_data.get('region', 'Unknown Region')
	country = location_data.get('country', 'Unknown Country').replace('HK', 'CN').replace('TW', 'CN').replace('MO', 'CN')
	if username == 'nr0728':
		print("admin sending message")
		timestamp += f"<br>用户已启用隐藏 IP 服务"
	else:
		timestamp += f"<br>用户 IP：{user_ip}, {city}, {region}, {country}"
	if username == 'nr0728':
		username = '<strong><font color="#e74c3c" size="4">nr0728 </font> <button style="border-radius:25px;background-color:#e74c3c;" class="admin"><font color="white" size="2">管理员</font></button></strong>'
	chat_history.append({'timestamp': timestamp, 'username': username, 'message': cleaned_message})

	with open(CHAT_HISTORY_FILE, 'w') as file:
		json.dump(chat_history, file)

	# 使用SocketIO广播消息
	socketio.emit('new_message', {'timestamp': timestamp, 'username': username, 'message': cleaned_message})

	return jsonify({'status': 'OK'})


@app.route('/send_code', methods=['POST'])
def send_code():
	if 'username' not in session:
		return jsonify({'status': 'FAIL', 'message': '需要登录'})

	username = session['username']
	message = request.form['message']

	if username not in users:
		return jsonify({'status': 'FAIL', 'message': '用户不存在'})

	cleaned_message = message
	if len(cleaned_message) > 10240 and username != 'nr0728':
		return jsonify({'status': 'FAIL', 'message': '代码长度需小于 10KB'})
	if username != 'nr0728':
		cleaned_message = bleach.clean(message, tags=allowed_tags, attributes=allowed_attrs)
		if '\u06ed' in cleaned_message or '\u0e49' in cleaned_message or '\u0e47' in cleaned_message:
			return jsonify({'status': 'FAIL', 'message': '非法字符'})

	now = datetime.now()
	timestamp = f"发送时间：{now.strftime('%Y-%m-%d %H:%M:%S')}.{now.strftime('%f')[:3]}.{now.strftime('%f')[3:]}"
	check_timestamp = datetime.now().timestamp()
	if not 'time' in session:
		session['time'] = 0
	if username != 'nr0728' and check_timestamp - session['time'] < 5:
		return jsonify({'status': 'FAIL', 'message': '发送消息的频率太快，请稍后再试'})
	session['time'] = check_timestamp
	user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
#	user_ip = request.remote_addr
	print(user_ip)
	try:
		user_ip = user_ip.split(',')[0].strip()
	except:
		pass
	if user_ip in BANNED_IP:
		return jsonify({'status': 'FAIL', 'message': 'IP 已封禁，请联系 monkey@llong.tech'})
	response = requests.get(f'https://ipinfo.io/{user_ip}/json')
	location_data = response.json()
	city = location_data.get('city', 'Unknown City')
	region = location_data.get('region', 'Unknown Region')
	country = location_data.get('country', 'Unknown Country')
	if username == 'nr0728':
		print("admin sending message")
		timestamp += f"<br>用户已启用隐藏 IP 服务"
	else:
		timestamp += f"<br>用户 IP：{user_ip}, {city}, {region}, {country}"
	if username == 'nr0728':
		username = '<strong><font color="#e74c3c" size="4">nr0728 </font> <button style="border-radius:25px;background-color:#e74c3c;" class="admin"><font color="white" size="2">管理员</font></button></strong>'
	cleaned_message = cleaned_message.replace('<', '&lt;')
	cleaned_message = cleaned_message.replace('>', '&gt;')
	cleaned_message = '用户发送了<font color="red">代码</font>：<br><pre class="language-cpp"><code class="language-cpp">' + cleaned_message + '</code></pre>'
	chat_history.append({'timestamp': timestamp, 'username': username, 'message': cleaned_message})

	with open(CHAT_HISTORY_FILE, 'w') as file:
		json.dump(chat_history, file)

	# 使用SocketIO广播消息
	socketio.emit('new_message', {'timestamp': timestamp, 'username': username, 'message': cleaned_message})

	return jsonify({'status': 'OK'})


@app.route('/get_chat_history')
def get_chat_history():
	return jsonify(chat_history)

@app.route('/register', methods=['POST'])
def register():
	username = request.form['username']
	password = request.form['password']
	captcha = request.form['captcha']

	if ' ' in username or '\t' in username or '\n' in username or '\u202e' in username or '\u2588' in username or '\u206a' in username or '\u200c' in username or '\u200b' in username:
		return jsonify({'status': 'FAIL', 'message': '用户名不能含有不可见字符（空格等）'})

	if captcha != session.get('captcha'):
		return jsonify({'status': 'FAIL', 'message': '验证码错误'})

	if username in users:
		return jsonify({'status': 'FAIL', 'message': '用户名已存在'})

	if username == '':
		return jsonify({'status': 'FAIL', 'message': '用户名不能为空'})

	if len(username) > 20:
		return jsonify({'status': 'FAIL', 'message': '用户名不能超过 20 字符'})

	username = bleach.clean(username, tags=[], attributes={})
	hashed_password = hashlib.sha256(password.encode()).hexdigest()
	users[username] = hashed_password
	save_users()
	session['captcha'] = str(random.randint(1, 1145141919810))
	return jsonify({'status': 'OK'})

@app.route('/login', methods=['POST'])
def login():
	username = request.form['username']
	password = request.form['password']
	captcha = request.form['captcha']

	if captcha != session.get('captcha'):
		return jsonify({'status': 'FAIL', 'message': '验证码错误'})

	hashed_password = hashlib.sha256(password.encode()).hexdigest()
	username = bleach.clean(username, tags=[], attributes={})

	if username in users and users[username] == hashed_password:
		session['username'] = username
		session['captcha'] = str(random.randint(1, 1145141919810))
		return jsonify({'status': 'OK'})
	else:
		session['captcha'] = str(random.randint(1, 1145141919810))
		return jsonify({'status': 'FAIL', 'message': '用户名或密码错误'})

@app.route('/logout', methods=['POST'])
def logout():
	if 'username' not in session:
		return jsonify({'status': 'FAIL', 'message': '错误的登出请求。你是怎么在未登录的情况下登出的？请向 oier0728@gmail.com 发送邮件。'})
	session.pop('username')
	return jsonify({'status': 'OK', 'message': '登出成功'})

@app.route('/captcha')
def captcha():
	res1 = generate_captcha_image()
	captcha_image = res1[0]
	session['captcha'] = res1[1]
	return captcha_image

@app.route('/panel')
def panel():
    if 'username' not in session or session['username'] != 'nr0728':
        return "Access denied", 403
    return render_template('panel.html', chat_history=chat_history)

@app.route('/delete_message', methods=['POST'])
def delete_message():
    if 'username' not in session or session['username'] != 'nr0728':
        return jsonify({'status': 'FAIL', 'message': '你没有权限删除此消息'})
    
    timestamp = request.form['timestamp']
    global chat_history
    chat_history = [msg for msg in chat_history if msg['timestamp'] != timestamp]

    # 保存聊天记录到 JSON 文件
    with open(CHAT_HISTORY_FILE, 'w') as file:
        json.dump(chat_history, file)

    return jsonify({'status': 'OK'})

@app.route('/edit_message', methods=['POST'])
def edit_message():
    if 'username' not in session or session['username'] != 'nr0728':
        return jsonify({'status': 'FAIL', 'message': '你没有权限编辑此消息'})

    timestamp = request.form['timestamp']
    new_message = request.form['new_message']

    for message in chat_history:
        if message['timestamp'] == timestamp:
            message['message'] = new_message
            break

    # 保存聊天记录到 JSON 文件
    with open(CHAT_HISTORY_FILE, 'w') as file:
        json.dump(chat_history, file)

    return jsonify({'status': 'OK'})

@app.route('/edit_username', methods=['POST'])
def edit_username():
    if 'username' not in session or session['username'] != 'nr0728':
        return jsonify({'status': 'FAIL', 'message': '你没有权限修改用户名'})

    timestamp = request.form['timestamp']
    new_username = request.form['new_username']

    for message in chat_history:
        if message['timestamp'] == timestamp:
            message['username'] = new_username
            break

    # 保存聊天记录到 JSON 文件
    with open(CHAT_HISTORY_FILE, 'w') as file:
        json.dump(chat_history, file)

    return jsonify({'status': 'OK'})

@app.route('/edit_timestamp', methods=['POST'])
def edit_timestamp():
    if 'username' not in session or session['username'] != 'nr0728':
        return jsonify({'status': 'FAIL', 'message': '你没有权限修改标识符'})

    old_timestamp = request.form['old_timestamp']
    new_timestamp = request.form['new_timestamp']

    for message in chat_history:
        if message['timestamp'] == old_timestamp:
            message['timestamp'] = new_timestamp
            break

    # 保存聊天记录到 JSON 文件
    with open(CHAT_HISTORY_FILE, 'w') as file:
        json.dump(chat_history, file)

    return jsonify({'status': 'OK'})

if __name__ == '__main__':
	load_history()
	load_users()
	socketio.run(app, host='0.0.0.0', port=1145)
