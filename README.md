<div align="center">
  <h1>Chat-Room</h1>
  <p>Made by nr0728</p>
</div>

## What's this?

使用 Python Flask 构建的一个小巧简便的聊天室。

## 部署

### Step 1. 克隆

```bash
git clone https://github.com/nr0728/Chat-Room.git
```

### Step 2. 安装

```bash
cd Chat-Room/
python -m pip install -r requirements.txt
```

### Step 3. 运行

```bash
python app.py
```

如果你想要在后台运行（例如服务器上部署等），请使用你的包管理器安装包 `screen`，并执行 `screen -S <新的终端名>`（e.g. `screen -S chatroom`），在其中执行 `python app.py` 即可。

使 screen 终端在后台运行：按下 `Ctrl+A` 后，松手再按 `D`。

恢复 screen 终端：`screen -r <终端名>`。

## 演示

<https://chat.llong.tech>。
