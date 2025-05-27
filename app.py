from flask import Flask, render_template, request, jsonify, session, send_file
import requests
import json
from datetime import datetime
import bleach
import hashlib
import random
from PIL import Image, ImageDraw, ImageFont
import io
from flask_socketio import SocketIO, emit
import getpass
import pyotp
import qrcode
import base64
import user_agents
import threading

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = "your_secret_key"  # 用于会话管理
socketio = SocketIO(app)

# 存储聊天记录的 JSON 文件路径
CHAT_HISTORY_FILE = "chat_history.json"
chat_history = []

# 存储用户信息的 JSON 文件路径
USER_DATA_FILE = "password.json"
users = {}

# 存储用户 2FA 密钥的 JSON 文件路径
USER_2FA_KEY_FILE = "2fa.json"
_2fa_keys = {}

# 存储用户 Loginkey 的 JSON 文件路径
USER_LOGINKEY_FILE = "loginkeys.json"
loginkeys = {}

# 私聊消息存储的 JSON 文件路径
PRIVATE_MSG_FILE = "private_messages.json"
private_messages_lock = threading.Lock()

# 封禁的 IP 列表
BANNED_IP = ["211.158.25.248", "122.224.219.246"]

# 管理员列表
admin_list = ["your-admin-username"]  # 请自定义

# 允许的 HTML 标签和属性白名单
allowed_tags = ["p", "br"]
allowed_attrs = {"*": ["style"], "p": ["style"]}


def PC_check(request):
    user_agent = request.headers.get("User-Agent")
    # return False  # DEBUG
    return user_agents.parse(user_agent).is_pc


def shuffle_string(s):
    s_list = list(s)
    random.shuffle(s_list)
    return "".join(s_list)


def load_history():
    global chat_history
    try:
        with open(CHAT_HISTORY_FILE, "r") as jFile:
            chat_history = json.load(jFile)
    except FileNotFoundError:
        chat_history = []


def load_users():
    global users
    try:
        with open(USER_DATA_FILE, "r") as file:
            users = json.load(file)
    except FileNotFoundError:
        users = {}


def load_2fa_keys():
    global _2fa_keys
    try:
        with open(USER_2FA_KEY_FILE, "r") as file:
            _2fa_keys = json.load(file)
    except FileNotFoundError:
        _2fa_keys = {}


# 加载 Loginkey 数据
def load_loginkeys():
    global loginkeys
    try:
        with open(USER_LOGINKEY_FILE, "r") as file:
            loginkeys = json.load(file)
    except FileNotFoundError:
        loginkeys = {}


def save_users():
    with open(USER_DATA_FILE, "w") as file:
        json.dump(users, file)


def save_2fa_keys():
    with open(USER_2FA_KEY_FILE, "w") as file:
        json.dump(_2fa_keys, file)


# 保存 Loginkey 数据
def save_loginkeys():
    with open(USER_LOGINKEY_FILE, "w") as file:
        json.dump(loginkeys, file)


characters = "wertyupadfghjkxcvbnm34578"


def selectedCharacters(length):
    return "".join(random.choice(characters) for _ in range(length))


def getColor():
    return (random.randint(0, 66), random.randint(0, 66), random.randint(0, 66))


def getColor2():
    return (
        random.randint(233, 250),
        random.randint(233, 250),
        random.randint(233, 250),
    )


def generate_captcha_image(size=(120, 60), characterNumber=5, bgcolor=getColor2()):
    imageTemp = Image.new("RGB", size, bgcolor)
    try:
        font = ImageFont.truetype("arial.ttf", 25)
    except OSError:
        font = ImageFont.load_default()
    draw = ImageDraw.Draw(imageTemp)
    text = selectedCharacters(characterNumber)
    # 修正 textbbox 的调用
    bbox = draw.textbbox((0, 0), text, font=font)
    width = bbox[2] - bbox[0]
    height = bbox[3] - bbox[1]
    offset = 2
    for i in range(characterNumber):
        offset += width // characterNumber
        position = (offset, (size[1] - height) // 2 + random.randint(-10, 10))
        draw.text(xy=position, text=text[i], font=font, fill=getColor())

    imageFinal = Image.new("RGB", size, bgcolor)
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
        draw.point(
            (random.randint(0, size[0]), random.randint(0, size[1])), fill=getColor()
        )
    for i in range(3):
        start = (0, random.randint(0, size[1] - 1))
        end = (size[0], random.randint(0, size[1] - 1))
        draw.line([start, end], fill=getColor(), width=1)
    for i in range(3):
        # 确保 y1 >= y0
        start_y = random.randint(0, size[1] // 2)
        end_y = random.randint(start_y, size[1])
        start = (-50, start_y)
        end = (size[0] + 10, end_y)
        draw.arc(start + end, 0, 360, fill=getColor())

    buf = io.BytesIO()
    imageFinal.save(buf, format="PNG")
    buf.seek(0)
    return (buf, text)


def get_private_key(user1, user2):
    # 按字典序拼接，保证唯一性
    return "|".join(sorted([user1, user2]))


def load_private_messages():
    try:
        with open(PRIVATE_MSG_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_private_messages(data):
    with open(PRIVATE_MSG_FILE, "w") as f:
        json.dump(data, f)


@app.route("/")
def index():
    if PC_check(request):
        return render_template("index.html")
    return render_template("m_index.html")


@app.route("/user_status", methods=["POST"])
def user_status():
    load_users()
    load_2fa_keys()
    print("fetching user status")
    username = session.get("username")
    print("fetching user status: get")
    print(_2fa_keys)
    print(username)
    if not username:
        return jsonify({"status": "FAIL", "message": "login required"})
    is_2fa_enabled = username in _2fa_keys
    if username in admin_list:
        username = (
            '<strong><font color="#e74c3c" size="4">'
            + username
            + ' </font><button style="border-radius:25px;background-color:#e74c3c;" class="admin"><font color="white" size="2">管理员</font></button></strong>'
        )
    return jsonify(
        {"status": "OK", "message": username, "is_2fa_enabled": is_2fa_enabled}
    )


@app.route("/user_status_", methods=["POST"])
def user_status_():
    load_users()
    load_2fa_keys()
    print("fetching user status")
    username = request.form.get("username")
    print("fetching user status: get")
    print(_2fa_keys)
    print(username)
    if not username:
        return jsonify({"status": "FAIL", "message": "login required"})
    is_2fa_enabled = username in _2fa_keys
    if username in admin_list:
        username = (
            '<strong><font color="#e74c3c" size="4">'
            + username
            + ' </font><button style="border-radius:25px;background-color:#e74c3c;" class="admin"><font color="white" size="2">管理员</font></button></strong>'
        )
    return jsonify(
        {"status": "OK", "message": username, "is_2fa_enabled": is_2fa_enabled}
    )


@app.route("/send_message", methods=["POST"])
def send_message():
    if "username" not in session:
        return jsonify({"status": "FAIL", "message": "需要登录"})

    username = session["username"]
    message = request.form["message"]

    if username not in users:
        return jsonify({"status": "FAIL", "message": "用户不存在"})

    cleaned_message = message
    if len(cleaned_message) > 100 and username not in admin_list:
        return jsonify({"status": "FAIL", "message": "消息长度需小于 100 字符"})
    if username not in admin_list:
        cleaned_message = bleach.clean(
            message, tags=allowed_tags, attributes=allowed_attrs
        )
        if (
            "\u06ed" in cleaned_message
            or "\u0e49" in cleaned_message
            or "\u0e47" in cleaned_message
        ):
            return jsonify({"status": "FAIL", "message": "非法字符"})

    now = datetime.now()
    timestamp = f"发送时间：{now.strftime('%Y-%m-%d %H:%M:%S')}.{now.strftime('%f')[:3]}.{now.strftime('%f')[3:]}"
    check_timestamp = datetime.now().timestamp()
    if not "time" in session:
        session["time"] = 0
    if username not in admin_list and check_timestamp - session["time"] < 5:
        return jsonify({"status": "FAIL", "message": "发送消息的频率太快，请稍后再试"})
    session["time"] = check_timestamp
    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    # user_ip = request.remote_addr
    print(user_ip)
    try:
        user_ip = user_ip.split(",")[0].strip()
    except:
        pass
    if user_ip in BANNED_IP:
        return jsonify(
            {"status": "FAIL", "message": "IP 已封禁，请联系 monkey@llong.tech"}
        )
    try:
        response = requests.get(f"https://ipinfo.io/{user_ip}/json")
        location_data = response.json()
        city = location_data.get("city", "Unknown City")
        region = location_data.get("region", "Unknown Region")
        country = (
            location_data.get("country", "Unknown Country")
            .replace("HK", "CN")
            .replace("TW", "CN")
            .replace("MO", "CN")
        )
    except requests.RequestException:
        city = "Unknown City"
        region = "Unknown Region"
        country = "Unknown Country"

    if username in admin_list:
        print("admin sending message")
        timestamp += f"<br>用户已启用隐藏 IP 服务"
    else:
        timestamp += f"<br>用户 IP：{user_ip}, {city}, {region}, {country}"
    if username in admin_list:
        username = (
            '<strong><font color="#e74c3c" size="4">'
            + username
            + ' </font> <button style="border-radius:25px;background-color:#e74c3c;" class="admin"><font color="white" size="2">管理员</font></button></strong>'
        )
    chat_history.append(
        {"timestamp": timestamp, "username": username, "message": cleaned_message}
    )

    with open(CHAT_HISTORY_FILE, "w") as file:
        json.dump(chat_history, file)

    # 使用SocketIO广播消息
    socketio.emit(
        "new_message",
        {"timestamp": timestamp, "username": username, "message": cleaned_message},
    )

    return jsonify({"status": "OK"})


@app.route("/send_code", methods=["POST"])
def send_code():
    if "username" not in session:
        return jsonify({"status": "FAIL", "message": "需要登录"})

    username = session["username"]
    message = request.form["message"]

    if username not in users:
        return jsonify({"status": "FAIL", "message": "用户不存在"})

    cleaned_message = message
    if len(cleaned_message) > 10240 and username not in admin_list:
        return jsonify({"status": "FAIL", "message": "代码长度需小于 10KB"})
    if username not in admin_list:
        cleaned_message = bleach.clean(
            message, tags=allowed_tags, attributes=allowed_attrs
        )
        if (
            "\u06ed" in cleaned_message
            or "\u0e49" in cleaned_message
            or "\u0e47" in cleaned_message
        ):
            return jsonify({"status": "FAIL", "message": "非法字符"})

    now = datetime.now()
    timestamp = f"发送时间：{now.strftime('%Y-%m-%d %H:%M:%S')}.{now.strftime('%f')[:3]}.{now.strftime('%f')[3:]}"
    check_timestamp = datetime.now().timestamp()
    if not "time" in session:
        session["time"] = 0
    if username not in admin_list and check_timestamp - session["time"] < 5:
        return jsonify({"status": "FAIL", "message": "发送消息的频率太快，请稍后再试"})
    session["time"] = check_timestamp
    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    # user_ip = request.remote_addr
    print(user_ip)
    try:
        user_ip = user_ip.split(",")[0].strip()
    except:
        pass
    if user_ip in BANNED_IP:
        return jsonify(
            {"status": "FAIL", "message": "IP 已封禁，请联系 monkey@llong.tech"}
        )
    try:
        response = requests.get(f"https://ipinfo.io/{user_ip}/json")
        location_data = response.json()
        city = location_data.get("city", "Unknown City")
        region = location_data.get("region", "Unknown Region")
        country = location_data.get("country", "Unknown Country")
    except requests.RequestException:
        city = "Unknown City"
        region = "Unknown Region"
        country = "Unknown Country"
    if username in admin_list:
        print("admin sending message")
        timestamp += f"<br>用户已启用隐藏 IP 服务"
    else:
        timestamp += f"<br>用户 IP：{user_ip}, {city}, {region}, {country}"
    if username in admin_list:
        username = (
            '<strong><font color="#e74c3c" size="4">'
            + username
            + ' </font> <button style="border-radius:25px;background-color:#e74c3c;" class="admin"><font color="white" size="2">管理员</font></button></strong>'
        )
    cleaned_message = cleaned_message.replace("<", "&lt;")
    cleaned_message = cleaned_message.replace(">", "&gt;")
    cleaned_message = (
        '用户发送了<font color="red">代码</font>：<br><pre class="language-cpp"><code class="language-cpp">'
        + cleaned_message
        + "</code></pre>"
    )
    chat_history.append(
        {"timestamp": timestamp, "username": username, "message": cleaned_message}
    )

    with open(CHAT_HISTORY_FILE, "w") as file:
        json.dump(chat_history, file)

    # 使用SocketIO广播消息
    socketio.emit(
        "new_message",
        {"timestamp": timestamp, "username": username, "message": cleaned_message},
    )

    return jsonify({"status": "OK"})


@app.route("/get_chat_history")
def get_chat_history():
    return jsonify(chat_history)


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    captcha = request.form["captcha"]

    if (
        " " in username
        or "\t" in username
        or "\n" in username
        or "\u202e" in username
        or "\u2588" in username
        or "\u206a" in username
        or "\u200c" in username
        or "\u200b" in username
    ):
        return jsonify(
            {"status": "FAIL", "message": "用户名不能含有不可见字符（空格等）"}
        )

    if captcha != session.get("captcha"):
        return jsonify({"status": "FAIL", "message": "验证码错误"})

    if username in users:
        return jsonify({"status": "FAIL", "message": "用户名已存在"})

    if username == "":
        return jsonify({"status": "FAIL", "message": "用户名不能为空"})

    if len(username) > 20:
        return jsonify({"status": "FAIL", "message": "用户名不能超过 20 字符"})

    username = bleach.clean(username, tags=[], attributes={})
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    users[username] = hashed_password
    save_users()
    session["captcha"] = str(random.randint(1, 1145141919810))
    return jsonify({"status": "OK"})


@app.route("/register_loginkey", methods=["POST"])
def register_loginkey():
    if "username" not in session:
        return jsonify({"status": "FAIL", "message": "需要登录"})

    username = session["username"]
    if username not in users:
        return jsonify({"status": "FAIL", "message": "用户不存在"})

    # 如果启用了 2FA，则需要验证 2FA
    if username in _2fa_keys:
        code = request.form.get("code")
        if not code:
            return jsonify({"status": "FAIL", "message": "需要提供 2FA 验证码"})
        totp = pyotp.TOTP(_2fa_keys[username])
        if not totp.verify(code):
            return jsonify({"status": "FAIL", "message": "2FA 验证失败"})

    # 生成唯一的 Loginkey
    while True:
        random_base32 = pyotp.random_base32()
        loginkey = hashlib.sha256(
            shuffle_string(
                f"{username}{random_base32}{pyotp.TOTP(random_base32).now()}"
            ).encode()
        ).hexdigest()
        del random_base32
        # 检查 Loginkey 是否已存在
        if loginkey not in loginkeys:
            break

    # 保存 Loginkey
    loginkeys[loginkey] = username
    save_loginkeys()

    return jsonify({"status": "OK", "loginkey": loginkey})


def register_admin(username, password):
    username = bleach.clean(username, tags=[], attributes={})
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    users[username] = hashed_password
    save_users()


@app.route("/login", methods=["POST"])
def login():
    # 获取用户输入的用户名、密码和验证码
    username = request.form["username"]
    password = request.form["password"]
    captcha = request.form["captcha"]

    if captcha != session.get("captcha"):
        return jsonify({"status": "FAIL", "message": "验证码错误"})

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    username = bleach.clean(username, tags=[], attributes={})

    if username in users and users[username] == hashed_password:
        # 设置会话
        session["captcha"] = str(random.randint(1, 1145141919810))

        # 如果用户启用了 2FA，则需要验证 2FA
        if username in _2fa_keys:
            code = request.form.get("code")
            if not code:
                return jsonify({"status": "FAIL", "message": "需要提供 2FA 验证码"})
            totp = pyotp.TOTP(_2fa_keys[username])
            if not totp.verify(code):
                return jsonify({"status": "FAIL", "message": "2FA 验证失败"})

        # 设置会话
        session["username"] = username

        return jsonify({"status": "OK"})
    else:
        session["captcha"] = str(random.randint(1, 1145141919810))
        return jsonify({"status": "FAIL", "message": "用户名或密码错误"})


@app.route("/login_with_loginkey", methods=["POST"])
def login_with_loginkey():
    loginkey = request.form.get("loginkey")

    # 检查 Loginkey 是否存在并有效
    if loginkey in loginkeys:
        username = loginkeys[loginkey]
    else:
        return jsonify({"status": "FAIL", "message": "无效的 Loginkey"})

    # 设置会话
    session["username"] = username
    return jsonify({"status": "OK", "message": "登录成功"})


@app.route("/logout", methods=["POST"])
def logout():
    if "username" not in session:
        return jsonify(
            {
                "status": "FAIL",
                "message": "错误的登出请求。你是怎么在未登录的情况下登出的？请向 oier0728@gmail.com 发送邮件。",
            }
        )
    session.pop("username")
    return jsonify({"status": "OK", "message": "登出成功"})


@app.route("/captcha")
def captcha():
    res1 = generate_captcha_image()
    captcha_image = res1[0]
    session["captcha"] = res1[1]
    # 返回图片时需要设置响应头
    return send_file(captcha_image, mimetype="image/png")


@app.route("/panel")
def panel():
    if "username" not in session or session["username"] not in admin_list:
        return "Access denied", 403
    if PC_check(request):
        return render_template("panel.html", chat_history=chat_history)
    return render_template("m_panel.html", chat_history=chat_history)


@app.route("/delete_message", methods=["POST"])
def delete_message():
    if "username" not in session or session["username"] not in admin_list:
        return jsonify({"status": "FAIL", "message": "你没有权限删除此消息"})

    timestamp = request.form["timestamp"]
    global chat_history
    chat_history = [msg for msg in chat_history if msg["timestamp"] != timestamp]

    # 保存聊天记录到 JSON 文件
    with open(CHAT_HISTORY_FILE, "w") as file:
        json.dump(chat_history, file)

    return jsonify({"status": "OK"})


@app.route("/edit_message", methods=["POST"])
def edit_message():
    if "username" not in session or session["username"] not in admin_list:
        return jsonify({"status": "FAIL", "message": "你没有权限编辑此消息"})

    timestamp = request.form["timestamp"]
    new_message = request.form["new_message"]

    for message in chat_history:
        if message["timestamp"] == timestamp:
            message["message"] = new_message
            break

    # 保存聊天记录到 JSON 文件
    with open(CHAT_HISTORY_FILE, "w") as file:
        json.dump(chat_history, file)

    return jsonify({"status": "OK"})


@app.route("/edit_username", methods=["POST"])
def edit_username():
    if "username" not in session or session["username"] not in admin_list:
        return jsonify({"status": "FAIL", "message": "你没有权限修改用户名"})

    timestamp = request.form["timestamp"]
    new_username = request.form["new_username"]

    for message in chat_history:
        if message["timestamp"] == timestamp:
            message["username"] = new_username
            break

    # 保存聊天记录到 JSON 文件
    with open(CHAT_HISTORY_FILE, "w") as file:
        json.dump(chat_history, file)

    return jsonify({"status": "OK"})


@app.route("/edit_timestamp", methods=["POST"])
def edit_timestamp():
    if "username" not in session or session["username"] not in admin_list:
        return jsonify({"status": "FAIL", "message": "你没有权限修改标识符"})

    old_timestamp = request.form["old_timestamp"]
    new_timestamp = request.form["new_timestamp"]

    for message in chat_history:
        if message["timestamp"] == old_timestamp:
            message["timestamp"] = new_timestamp
            break

    # 保存聊天记录到 JSON 文件
    with open(CHAT_HISTORY_FILE, "w") as file:
        json.dump(chat_history, file)

    return jsonify({"status": "OK"})


@app.route("/enable_2fa", methods=["POST"])
def enable_2fa():
    if "username" not in session:
        return jsonify({"status": "FAIL", "message": "需要登录"})

    username = session["username"]
    if username not in users:
        return jsonify({"status": "FAIL", "message": "用户不存在"})

    if username in _2fa_keys:
        return jsonify({"status": "FAIL", "message": "2FA 已启用"})

    # 生成 2FA 密钥
    secret = pyotp.random_base32()
    session["2fa_temp_secret"] = secret  # 暂存密钥

    # 生成二维码
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="Chat Room App"
    )
    qr = qrcode.make(otp_uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    buf.seek(0)
    qr_url = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"

    return jsonify({"status": "OK", "qr_url": qr_url, "secret_key": secret})


@app.route("/verify_2fa", methods=["POST"])
def verify_2fa():
    if "username" not in session:
        return jsonify({"status": "FAIL", "message": "需要登录"})

    username = session["username"]
    temp_secret = session.get("2fa_temp_secret")  # 获取暂存密钥

    if not temp_secret and username not in _2fa_keys:
        return jsonify({"status": "FAIL", "message": "2FA 未启用"})

    code = request.form["code"]
    totp = pyotp.TOTP(temp_secret if temp_secret else _2fa_keys[username])

    if totp.verify(code):
        if temp_secret:  # 如果是首次验证，保存密钥
            _2fa_keys[username] = temp_secret
            save_2fa_keys()
            session.pop("2fa_temp_secret", None)  # 移除暂存密钥
        session["2fa_verified"] = True
        return jsonify({"status": "OK", "message": "2FA 验证成功"})
    else:
        return jsonify({"status": "FAIL", "message": "2FA 验证失败"})


@app.route("/disable_2fa", methods=["POST"])
def disable_2fa():
    if "username" not in session:
        return jsonify({"status": "FAIL", "message": "需要登录"})

    username = session["username"]
    if username not in _2fa_keys:
        return jsonify({"status": "FAIL", "message": "2FA 未启用"})

    # 获取用户提交的 2FA 验证码
    code = request.form.get("code")
    if not code:
        return jsonify({"status": "FAIL", "message": "需要提供 2FA 验证码"})

    # 验证 2FA 验证码
    totp = pyotp.TOTP(_2fa_keys[username])
    if not totp.verify(code):
        return jsonify({"status": "FAIL", "message": "2FA 验证失败"})

    # 删除用户的 2FA 密钥
    del _2fa_keys[username]
    save_2fa_keys()
    return jsonify({"status": "OK", "message": "2FA 已禁用"})


def add_2fa_for_user(username):
    _2fa_keys[username] = pyotp.random_base32()
    save_2fa_keys()
    return _2fa_keys[username]


@socketio.on("join_private")
def on_join_private(data):
    # data: {"username": "...">
    username = data.get("username")
    if username:
        # 让每个用户加入自己的私聊房间
        from flask_socketio import join_room

        join_room(f"user_{username}")


@app.route("/send_private_message", methods=["POST"])
def send_private_message():
    if "username" not in session:
        return jsonify({"status": "FAIL", "message": "需要登录"})
    from_user = session["username"]
    to_user = request.form.get("to_user")
    message = request.form.get("message")
    if not to_user or not message:
        return jsonify({"status": "FAIL", "message": "参数缺失"})
    if from_user == to_user:
        return jsonify({"status": "FAIL", "message": "不能给自己发私聊"})
    load_users()
    if to_user not in users:
        return jsonify({"status": "FAIL", "message": "目标用户不存在"})
    cleaned_message = bleach.clean(message, tags=allowed_tags, attributes=allowed_attrs)
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S.%f")
    msg_obj = {
        "from": from_user,
        "to": to_user,
        "message": cleaned_message,
        "timestamp": timestamp,
    }
    with private_messages_lock:
        data = load_private_messages()
        key = get_private_key(from_user, to_user)
        if key not in data:
            data[key] = []
        data[key].append(msg_obj)
        save_private_messages(data)
    # SocketIO推送（只发给目标用户和自己）
    for user in [from_user, to_user]:
        socketio.emit("private_message", msg_obj, room=f"user_{user}")
    return jsonify({"status": "OK"})


@app.route("/get_private_history", methods=["POST"])
def get_private_history():
    if "username" not in session:
        return jsonify({"status": "FAIL", "message": "需要登录"})
    user1 = session["username"]
    user2 = request.form.get("with_user")
    if not user2:
        return jsonify({"status": "FAIL", "message": "参数缺失"})
    load_users()
    if user2 not in users:
        return jsonify({"status": "FAIL", "message": "目标用户不存在"})
    with private_messages_lock:
        data = load_private_messages()
        key = get_private_key(user1, user2)
        msgs = data.get(key, [])
    return jsonify({"status": "OK", "messages": msgs})


@app.route("/get_all_users", methods=["POST"])
def get_all_users():
    load_users()
    return jsonify({"status": "OK", "users": list(users.keys())})


@app.route("/recall_message", methods=["POST"])
def recall_message():
    if "username" not in session:
        return jsonify({"status": "FAIL", "message": "需要登录"})
    username = session["username"]
    timestamp = request.form.get("timestamp")
    if not timestamp:
        return jsonify({"status": "FAIL", "message": "参数缺失"})
    global chat_history
    idx = None
    for i, msg in enumerate(chat_history):
        if msg["timestamp"] == timestamp:
            # 判断权限：本人或管理员
            raw_username = msg["username"]
            if raw_username.startswith("<strong>"):
                import re

                raw_username = re.sub(r"<[^>]+>", "", raw_username)
                raw_username = raw_username.replace("管理员", "").strip()
            if username == raw_username or username in admin_list:
                idx = i
            else:
                return jsonify({"status": "FAIL", "message": "无权撤回该消息"})
            break
    if idx is not None:
        del chat_history[idx]
        with open(CHAT_HISTORY_FILE, "w") as file:
            json.dump(chat_history, file)
        # 通知所有人刷新
        socketio.emit(
            "new_message", {"timestamp": timestamp, "username": "", "message": ""}
        )
        return jsonify({"status": "OK"})
    else:
        return jsonify({"status": "FAIL", "message": "未找到该消息"})


if __name__ == "__main__":
    load_history()
    load_users()
    load_2fa_keys()
    load_loginkeys()
    for admin in admin_list:
        if admin not in users:
            prompt = f"The administrator account '{admin}' is not currently registered. Please enter the password for this user to proceed with automatic registration. To skip this step, simply press Enter: "
            admin_password = getpass.getpass(prompt)
            if admin_password:
                register_admin(admin, admin_password)
                print("Registered admin account: ", admin)
    print("Running on port 1145")
    socketio.run(app, host="0.0.0.0", port=1145)
else:
    load_history()
    load_users()
    load_2fa_keys()
    load_loginkeys()
