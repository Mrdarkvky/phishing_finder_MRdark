import pygame
import subprocess
import re
import urllib.parse
import ipaddress
import pyttsx3
import locale
import requests
import random
import threading
import time
import pyperclip
from bs4 import BeautifulSoup
import socket
import tldextract
import joblib
import numpy as np
import os

model_path = r"C:\Users\nivas\3D Objects\HackThreat\phishing_model.pkl"

if not os.path.exists(model_path):
    print("Error: AI Model file not found!")
    model = None
else:
    try:
        model = joblib.load(model_path)
        print("AI Model Loaded Successfully!")
    except Exception as e:
        print(f"Error loading AI model: {e}")
        model = None

pygame.init()
pygame.font.init()

WIDTH, HEIGHT = 1000, 700
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("DARK - Phishing Detection AI")

BLACK = (0, 0, 0)
DARK_BLUE = (0, 20, 40)
BLUE = (0, 150, 255)
RED = (255, 50, 50)
GREEN = (50, 255, 100)
WHITE = (255, 255, 255)
GRAY = (100, 100, 100)
YELLOW = (255, 255, 0)

title_font = pygame.font.SysFont("Arial", 48, bold=True)
header_font = pygame.font.SysFont("Arial", 36)
text_font = pygame.font.SysFont("Arial", 20)
result_font = pygame.font.SysFont("Arial", 24, bold=True)

speech_active = False
url_history = []
current_history_index = -1
undo_history = []
undo_position = -1
max_undo_steps = 20
engine = None

def init_tts():
    global engine
    try:
        engine = pyttsx3.init()
        voices = engine.getProperty('voices')
        for voice in voices:
            if 'english' in voice.name.lower():
                engine.setProperty('voice', voice.id)
                break
    except Exception as e:
        print(f"TTS initialization error: {e}")

tts_thread = threading.Thread(target=init_tts)
tts_thread.daemon = True
tts_thread.start()

core_radius = 100
core_x, core_y = WIDTH // 2, HEIGHT // 3
core_particles = []
core_pulse = 0
core_pulse_direction = 1
particle_radius = 3
particle_count = 120
particle_min_speed = 0.5
particle_max_speed = 2.0
scanning = False
scan_progress = 0
scan_result = None
scan_details = []
url_input = ""
input_active = True
cursor_visible = True
cursor_position = 0
cursor_time = 0
url_status = ""

for i in range(particle_count):
    angle = random.uniform(0, 360)
    distance = random.uniform(core_radius * 0.8, core_radius * 1.2)
    speed = random.uniform(particle_min_speed, particle_max_speed)
    x = core_x + distance * pygame.math.Vector2(1, 0).rotate(angle).x
    y = core_y + distance * pygame.math.Vector2(1, 0).rotate(angle).y
    core_particles.append([x, y, angle, speed])

input_box = pygame.Rect(WIDTH // 4, HEIGHT // 2, WIDTH // 2, 50)

def speak_text(text):
    if engine is None:
        return
    global speech_active
    def speak_worker():
        try:
            global speech_active
            if speech_active:
                return
            speech_active = True
            engine.say(text)
            engine.runAndWait()
            speech_active = False
        except Exception as e:
            print(f"Error with TTS: {e}")
            speech_active = False
    if not speech_active:
        speech_thread = threading.Thread(target=speak_worker)
        speech_thread.daemon = True
        speech_thread.start()

def is_valid_url(url):
    try:
        result = urllib.parse.urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False
        ext = tldextract.extract(url)
        if not ext.suffix:
            return False
        return True
    except Exception:
        return False

def is_temporary_domain(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        temp_domains = ["temp.com", "temporary.com", "tempurl.com", "10minutemail.com", "guerrillamail.com", "sharklasers.com", "disposable.com", "mailinator.com", "yopmail.com", "tempmail.net"]
        domain = parsed_url.netloc.lower()
        for temp in temp_domains:
            if domain.endswith(temp) or domain == temp:
                return True
        return False
    except:
        return False

def check_url(url):
    results = []
    is_suspicious = False
    try:
        parsed_url = urllib.parse.urlparse(url)
        try:
            ipaddress.ip_address(parsed_url.netloc)
            results.append("WARNING: URL uses an IP address instead of a domain.")
            is_suspicious = True
        except ValueError:
            pass
        if len(url) > 75:
            results.append("WARNING: URL is very long.")
            is_suspicious = True
        suspicious_words = ["login", "signin", "bank", "account", "verify", "secure", "update"]
        found_words = [word for word in suspicious_words if word in url.lower()]
        if found_words:
            results.append(f"WARNING: URL contains suspicious words: {', '.join(found_words)}")
            is_suspicious = True
        if parsed_url.scheme != "https":
            results.append("WARNING: URL does not use HTTPS.")
            is_suspicious = True
    except Exception as e:
        results.append(f"Error parsing URL: {str(e)}")
        is_suspicious = True
    return is_suspicious, results
