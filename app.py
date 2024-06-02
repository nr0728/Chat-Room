from flask import Flask, render_template, request, jsonify, session
import string
import json
from datetime import datetime
import bleach
import hashlib
import random
from PIL import Image, ImageDraw, ImageFont
import io
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # 用于会话管理

# 存储聊天记录的 JSON 文件路径
CHAT_HISTORY_FILE = 'chat_history.json'
chat_history = []

# 存储用户信息的 JSON 文件路径
USER_DATA_FILE = 'password.json'
users = {}

# 允许的 HTML 标签和属性白名单
allowed_tags = ['p', 'br']
allowed_attrs = {'*': ['style'], 'p': ['style']}

def load_history():
    global chat_history
    try:
        jFile = open(CHAT_HISTORY_FILE)
        chat_history = json.load(jFile)
    except FileNotFoundError:
            chat_history = []

# 加载用户数据
def load_users():
    global users
    try:
        with open(USER_DATA_FILE, 'r') as file:
            users = json.load(file)
    except FileNotFoundError:
        users = {}

# 保存用户数据
def save_users():
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(users, file)

 
#所有可能的字符，主要是英文字母和数字
characters="wertyupadfghjkzxcvbnm234578"
 
#获取指定长度的字符串
def selectedCharacters(length):
    result=""
    for i in range(length):
        result+=random.choice(characters)
    return result
 
def getColor():
    r=random.randint(0,66)
    g=random.randint(0,66)
    b=random.randint(0,66)
    return (r,g,b)

def getColor2():
    r=random.randint(233,250)
    g=random.randint(233,250)
    b=random.randint(233,250)
    return (r,g,b)
# 生成验证码图片
def generate_captcha_image(size=(120,60),characterNumber=5,bgcolor=getColor2()):
    imageTemp=Image.new('RGB',size,bgcolor)
    font=ImageFont.truetype('arial.ttf',25)
    draw=ImageDraw.Draw(imageTemp)
    text=selectedCharacters(characterNumber)
    width,heigth=draw.textsize(text,font)
    #绘制验证码字符串
    offset=2
    for i in range(characterNumber):
        offset+=width//characterNumber
        position=(offset,(size[1]-heigth)//2+random.randint(-10,10))
        draw.text(xy=position,text=text[i],font=font,fill=getColor())
    #对验证码图片进行简单变换，这里采取简单的点运算
    imageFinal=Image.new('RGB',size,bgcolor)
    pixelsFinal=imageFinal.load()
    pixelsTemp=imageTemp.load()
    for y in range(0,size[1]):
        offset=random.randint(-1,1)
        for x in range(0,size[0]):
            newx=x+offset
            if newx>=size[0]:
                newx=size[0]-1
            elif newx<0:
                newx=0
            pixelsFinal[newx,y]=pixelsTemp[x,y]
    draw=ImageDraw.Draw(imageFinal)
    #绘制干扰噪点像素
    for i in range(int(size[0]*size[1]*0.03)):
        draw.point((random.randint(0,size[0]),random.randint(0,size[1])),fill=getColor())
    #绘制干扰线条
    for i in range(3):
        start=(0,random.randint(0,size[1]-1))
        end=(size[0],random.randint(0,size[1]-1))
        draw.line([start,end],fill=getColor(),width=1)
    #绘制干扰弧线
    for i in range(3):
        start=(-50,50)
        end=(size[0]+10,random.randint(0,size[1]+10))
        draw.arc(start+end,0,360,fill=getColor())
    image = Image.new('RGB', (100, 40), color = (random.randint(50,200), random.randint(50,200), random.randint(50,200)))
    buf = io.BytesIO()
    imageFinal.save(buf, format='PNG')
    buf.seek(0)
#    return base64.b64encode(buf.getvalue()).decode('utf-8')
    return (buf,text)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user_status', methods=['POST'])
def user_status():
    if 'username' not in session:
        return jsonify({'status': 'FAIL', 'message': 'login required'})
    return jsonify({'status': 'OK', 'message': session['username']})

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({'status': 'FAIL', 'message': '需要登录'})

    username = session['username']
    message = request.form['message']
    
    # 对用户输入的消息进行 HTML 清理
    cleaned_message = message
    if username != 'nr0728':
        cleaned_message = bleach.clean(message, tags=allowed_tags, attributes=allowed_attrs)
    if len(cleaned_message) > 100 and username != 'nr0728':
        return jsonify({'status': 'FAIL', 'message': '消息长度需小于 100 字符'})

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    chat_history.append({'timestamp': timestamp, 'username': username, 'message': cleaned_message})

    # 保存聊天记录到 JSON 文件
    with open(CHAT_HISTORY_FILE, 'w') as file:
        json.dump(chat_history, file)

    return jsonify({'status': 'OK'})

@app.route('/get_chat_history')
def get_chat_history():
    return jsonify(chat_history)

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    captcha = request.form['captcha']
    
    if ' ' in username or '\t' in username or '\n' in username:
        return jsonify({'status': 'FAIL', 'message': '用户名不能含有不可见字符（空格等）'})

    if captcha != session['captcha']:
        return jsonify({'status': 'FAIL', 'message': '验证码错误'})

    if username in users:
        return jsonify({'status': 'FAIL', 'message': '用户名已存在'})

    if username == '':
        return jsonify({'status': 'FAIL', 'message': '用户名不能为空'})

    if len(username) > 20:
        return jsonify({'status': 'FAIL', 'message': '用户名不能超过 20 字符'})

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    users[username] = hashed_password
    save_users()
    return jsonify({'status': 'OK'})

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    captcha = request.form['captcha']
    
    # 验证验证码
    if captcha != session['captcha']:
        return jsonify({'status': 'FAIL', 'message': '验证码错误'})

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if username in users and users[username] == hashed_password:
        session['username'] = username
        return jsonify({'status': 'OK'})
    else:
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

if __name__ == '__main__':
    load_history()
    load_users()
    app.run(host='0.0.0.0', port=1145)


