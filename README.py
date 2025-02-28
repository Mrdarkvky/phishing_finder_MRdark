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
    
    def speak_worker():
        try:
            engine.say(text)
            engine.runAndWait()
        except Exception as e:
            print(f"Error with TTS: {e}")
    
    speech_thread = threading.Thread(target=speak_worker)
    speech_thread.daemon = True
    speech_thread.start()

def is_valid_url(url):
    """Check if the URL is valid in terms of format and existence"""
    try:
        result = urllib.parse.urlparse(url)
        
        if not all([result.scheme, result.netloc]):
            return False
        
        if '.' not in result.netloc:
            return False
            
        return True
    except:
        return False


def is_temporary_domain(url):
    """Check if the URL is from a temporary domain"""
    try:
        parsed_url = urllib.parse.urlparse(url)
        temp_domains = ["temp.com", "temporary.com", "tempurl.com", "10minutemail.com", 
                         "guerrillamail.com", "sharklasers.com", "disposable.com",
                         "mailinator.com", "yopmail.com", "tempmail.net"]
        
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

def check_shortening_service(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        shortening_services = [
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "short.link", 
            "ow.ly", "buff.ly", "rb.gy", "cutt.ly"
        ]
        if parsed_url.netloc in shortening_services:
            return True, "WARNING: URL uses a shortening service. Be cautious."
        return False, ""
    except Exception as e:
        return False, f"Error checking shortening service: {str(e)}"

def extract_title(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, timeout=5, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")
        title = soup.title.string if soup.title else None
        return title

    except requests.exceptions.RequestException as e:
        return f"Error fetching webpage: {str(e)}"
    except Exception as e:
        return f"Error parsing HTML: {str(e)}"

def scan_url(url):
    global scan_result, scan_details, scanning, url_status
    
    scan_details = []
    is_suspicious = False
    
    if not is_valid_url(url):
        scan_result = "INVALID"
        scan_details.append("Invalid URL format. Please enter a complete URL including http:// or https://")
        speak_text("Invalid URL format. Please enter a complete URL including protocol.")
        scanning = False
        return
  
    
    if is_temporary_domain(url):
        url_status = "TEMPORARY DOMAIN"
        scan_details.append("WARNING: This appears to be a temporary domain.")
        is_suspicious = True
    
    suspicious, results = check_url(url)
    if suspicious:
        is_suspicious = True
        scan_details.extend(results)
    
    shortened, result = check_shortening_service(url)
    if shortened:
        is_suspicious = True
        scan_details.append(result)
    
    title = extract_title(url)
    if title:
        scan_details.append(f"Webpage title: {title}")
    else:
        scan_details.append("Could not retrieve webpage title.")
    
    if is_suspicious:
        scan_result = "SUSPICIOUS"
        scan_details.append("This URL is potentially suspicious. Exercise caution!")
    else:
        scan_result = "SAFE"
        scan_details.append("This URL appears to be safe based on our checks.")
    
    speak_text(f"Scan complete. The URL is {scan_result}.")
    
    scanning = False
    
def draw_core():
  
    global core_pulse, core_pulse_direction
    core_pulse += 0.02 * core_pulse_direction
    if core_pulse >= 1.0:
        core_pulse_direction = -1
    elif core_pulse <= 0.0:
        core_pulse_direction = 1
    
    pulse_radius = core_radius * (1 + 0.1 * core_pulse)
    
    for i in range(5, 0, -1):
        alpha = 100 - i * 20
        if alpha < 0:
            alpha = 0
        
        surface = pygame.Surface((WIDTH, HEIGHT), pygame.SRCALPHA)
        
        if scan_result == "SUSPICIOUS":
            color = (RED[0], RED[1], RED[2], alpha)
        elif scan_result == "SAFE":
            color = (GREEN[0], GREEN[1], GREEN[2], alpha)
        elif scan_result == "INVALID":
            color = (YELLOW[0], YELLOW[1], YELLOW[2], alpha)
        else:
            color = (BLUE[0], BLUE[1], BLUE[2], alpha)
            
        pygame.draw.circle(
            surface, 
            color, 
            (int(core_x), int(core_y)), 
            int(pulse_radius + i * 4)
        )
        screen.blit(surface, (0, 0))
    
    if scanning:
        pygame.draw.circle(screen, DARK_BLUE, (int(core_x), int(core_y)), int(pulse_radius))
        if scan_progress > 0:
            pygame.draw.arc(
                screen,
                BLUE,
                (int(core_x - pulse_radius), int(core_y - pulse_radius), int(pulse_radius * 2), int(pulse_radius * 2)),
                0,
                scan_progress * 6.283,  # 2π
                int(pulse_radius // 10)
            )
    else:
        if scan_result == "SUSPICIOUS":
            color = RED
        elif scan_result == "SAFE":
            color = GREEN
        elif scan_result == "INVALID":
            color = YELLOW
        else:
            color = BLUE
        pygame.draw.circle(screen, color, (int(core_x), int(core_y)), int(pulse_radius))

def update_particles():
    if scanning:
        
        for particle in core_particles:
           
            target_angle = pygame.math.Vector2(core_x - particle[0], core_y - particle[1]).angle_to(pygame.math.Vector2(1, 0))
            particle[2] = target_angle + random.uniform(-20, 20)
            
            particle[3] = random.uniform(particle_max_speed, particle_max_speed * 2)
            
            particle[0] += particle[3] * pygame.math.Vector2(1, 0).rotate(particle[2]).x
            particle[1] += particle[3] * pygame.math.Vector2(1, 0).rotate(particle[2]).y
            

            if particle[0] < 0 or particle[0] > WIDTH or particle[1] < 0 or particle[1] > HEIGHT:
                
                angle = random.uniform(0, 360)
                distance = random.uniform(core_radius * 1.5, core_radius * 3)
                particle[0] = core_x + distance * pygame.math.Vector2(1, 0).rotate(angle).x
                particle[1] = core_y + distance * pygame.math.Vector2(1, 0).rotate(angle).y
    else:
        
        for particle in core_particles:
            
            to_core = pygame.math.Vector2(core_x - particle[0], core_y - particle[1])
            distance = to_core.length()
            
            
            if distance < core_radius * 0.8:
                
                particle[2] = to_core.angle_to(pygame.math.Vector2(1, 0)) + 90 + random.uniform(-10, 10)
            elif distance > core_radius * 2.0:
               
                particle[2] = to_core.angle_to(pygame.math.Vector2(1, 0)) + random.uniform(-20, 20)
            else:
                particle[2] = to_core.angle_to(pygame.math.Vector2(1, 0)) + 75 + random.uniform(-15, 15)
            
            particle[0] += particle[3] * pygame.math.Vector2(1, 0).rotate(particle[2]).x
            particle[1] += particle[3] * pygame.math.Vector2(1, 0).rotate(particle[2]).y

def draw_particles():
    for particle in core_particles:
       
        if scan_result == "SUSPICIOUS":
            color = RED
        elif scan_result == "SAFE":
            color = GREEN
        elif scan_result == "INVALID":
            color = YELLOW
        else:
            color = BLUE
        
        
        surface = pygame.Surface((particle_radius*2, particle_radius*2), pygame.SRCALPHA)
        pygame.draw.circle(surface, (*color, 180), (particle_radius, particle_radius), particle_radius)
        screen.blit(surface, (int(particle[0] - particle_radius), int(particle[1] - particle_radius)))

def draw_ui():
    title_surface = title_font.render("DARK AI", True, WHITE)
    subtitle_surface = text_font.render("Deep Analysis & Recognition Kernel", True, GRAY)
    screen.blit(title_surface, (WIDTH // 2 - title_surface.get_width() // 2, 20))
    screen.blit(subtitle_surface, (WIDTH // 2 - subtitle_surface.get_width() // 2, 70))
    
    pygame.draw.rect(screen, GRAY, input_box, 2)
    
    label = text_font.render("Enter URL to scan:", True, WHITE)
    screen.blit(label, (input_box.x, input_box.y - 30))
    
    if url_status:
        status_surface = text_font.render(url_status, True, YELLOW)
        screen.blit(status_surface, (input_box.x + input_box.width + 10, input_box.y + 15))
    
    if input_active:
        visible_input = url_input[:cursor_position] + ("|" if cursor_visible else " ") + url_input[cursor_position:]
    else:
        visible_input = url_input
    
    input_surface = text_font.render(visible_input, True, WHITE)
    screen.blit(input_surface, (input_box.x + 5, input_box.y + 15))
    
    button_width = 150
    button_height = 50
    button_x = WIDTH // 2 - button_width // 2
    button_y = input_box.y + input_box.height + 20
    button_rect = pygame.Rect(button_x, button_y, button_width, button_height)
    
    if scanning:
        pygame.draw.rect(screen, GRAY, button_rect)
        button_text = text_font.render("Scanning...", True, WHITE)
    else:
        pygame.draw.rect(screen, BLUE, button_rect)
        button_text = text_font.render("Scan URL", True, WHITE)
    
    screen.blit(button_text, (button_x + button_width // 2 - button_text.get_width() // 2, 
                             button_y + button_height // 2 - button_text.get_height() // 2))
    
    if scan_result:
        result_y = button_y + button_height + 30
        
        if scan_result == "SUSPICIOUS":
            result_text = result_font.render("RESULT: SUSPICIOUS", True, RED)
        elif scan_result == "SAFE":
            result_text = result_font.render("RESULT: SAFE", True, GREEN)
        elif scan_result == "INVALID":
            result_text = result_font.render("RESULT: INVALID URL", True, YELLOW)
        else:
            result_text = result_font.render(f"RESULT: {scan_result}", True, BLUE)
        
        screen.blit(result_text, (WIDTH // 2 - result_text.get_width() // 2, result_y))
        
        details_y = result_y + 40
        max_details = 5  
        
        for i, detail in enumerate(scan_details[:max_details]):
            detail_surface = text_font.render(detail, True, WHITE)
            screen.blit(detail_surface, (WIDTH // 4, details_y + i * 25))
        
        if len(scan_details) > max_details:
            more_text = text_font.render(f"... and {len(scan_details) - max_details} more details", True, GRAY)
            screen.blit(more_text, (WIDTH // 4, details_y + max_details * 25))

def save_for_undo():
    global undo_history, undo_position
    
    if undo_position == len(undo_history) - 1:
        undo_history.append((url_input, cursor_position))
        undo_position += 1
        if len(undo_history) > max_undo_steps:
            undo_history.pop(0)
            undo_position -= 1
    else:
        undo_history = undo_history[:undo_position + 1]
        undo_history.append((url_input, cursor_position))
        undo_position = len(undo_history) - 1

def undo():
    global url_input, cursor_position, undo_position
    
    if undo_position > 0:
        undo_position -= 1
        url_input, cursor_position = undo_history[undo_position]

def redo():
    global url_input, cursor_position, undo_position
    
    if undo_position < len(undo_history) - 1:
        undo_position += 1
        url_input, cursor_position = undo_history[undo_position]

def start_scan():
    global scanning, scan_progress, scan_result, url_history, current_history_index
    
    if url_input.strip() and not scanning:
        scanning = True
        scan_progress = 0
        scan_result = None
        
        if current_history_index < len(url_history) - 1:
            url_history = url_history[:current_history_index + 1]
        
        url_history.append(url_input)
        current_history_index = len(url_history) - 1
        
        scan_thread = threading.Thread(target=scan_url, args=(url_input,))
        scan_thread.daemon = True
        scan_thread.start()
        
        speak_text(f"Scanning {url_input}")

def navigate_history(direction):
    global current_history_index, url_input
    
    if direction == "back" and current_history_index > 0:
        current_history_index -= 1
        url_input = url_history[current_history_index]
    elif direction == "forward" and current_history_index < len(url_history) - 1:
        current_history_index += 1
        url_input = url_history[current_history_index]

running = True
clock = pygame.time.Clock()

def check_button_click(pos):
    button_width = 150
    button_height = 50
    button_x = WIDTH // 2 - button_width // 2
    button_y = input_box.y + input_box.height + 20
    button_rect = pygame.Rect(button_x, button_y, button_width, button_height)
    
    if button_rect.collidepoint(pos) and not scanning:
        return "scan"
    
    return None
undo_history.append((url_input, cursor_position))
undo_position = 0

while running:
    current_time = time.time()
    
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False
        elif event.type == pygame.MOUSEBUTTONDOWN:
            if input_box.collidepoint(event.pos):
                input_active = True
                click_x = event.pos[0] - input_box.x - 5
                test_widths = [text_font.size(url_input[:i])[0] for i in range(len(url_input) + 1)]
                closest_pos = min(range(len(test_widths)), key=lambda i: abs(test_widths[i] - click_x))
                cursor_position = closest_pos
            else:
                input_active = False
            
            button_action = check_button_click(event.pos)
            if button_action == "scan":
                start_scan()
        
        elif event.type == pygame.KEYDOWN:
            if input_active:
                old_input = url_input
                old_cursor = cursor_position
                
                if event.key == pygame.K_RETURN:
                    start_scan()
                elif event.key == pygame.K_BACKSPACE:
                    if cursor_position > 0:
                        url_input = url_input[:cursor_position-1] + url_input[cursor_position:]
                        cursor_position -= 1
                        save_for_undo()
                elif event.key == pygame.K_DELETE:
                    if cursor_position < len(url_input):
                        url_input = url_input[:cursor_position] + url_input[cursor_position+1:]
                        save_for_undo()
                elif event.key == pygame.K_LEFT:
                    if event.mod & pygame.KMOD_ALT:
                        navigate_history("back")
                    else:
                        cursor_position = max(0, cursor_position - 1)
                elif event.key == pygame.K_RIGHT:
                    if event.mod & pygame.KMOD_ALT:
                        navigate_history("forward")
                    else:
                        cursor_position = min(len(url_input), cursor_position + 1)
                elif event.key == pygame.K_HOME:
                    cursor_position = 0
                elif event.key == pygame.K_END:
                    cursor_position = len(url_input)
                elif event.key == pygame.K_a and event.mod & pygame.KMOD_CTRL:
                    cursor_position = len(url_input)
                elif event.key == pygame.K_z and event.mod & pygame.KMOD_CTRL:
                    if not (event.mod & pygame.KMOD_SHIFT):
                        undo()
                    else:
                        redo()
                elif event.key == pygame.K_y and event.mod & pygame.KMOD_CTRL:
                    redo()
                elif event.key == pygame.K_v and event.mod & pygame.KMOD_CTRL:
                    try:
                        clipboard_text = pyperclip.paste()
                        url_input = url_input[:cursor_position] + clipboard_text + url_input[cursor_position:]
                        cursor_position += len(clipboard_text)
                        save_for_undo()
                    except:
                        print("Clipboard access error")
                elif event.key == pygame.K_c and event.mod & pygame.KMOD_CTRL:
                    try:
                        pyperclip.copy(url_input)
                    except:
                        print("Clipboard access error")
                else:
                    url_input = url_input[:cursor_position] + event.unicode + url_input[cursor_position:]
                    cursor_position += len(event.unicode)
                    save_for_undo()
    if current_time - cursor_time > 0.5:
        cursor_visible = not cursor_visible
        cursor_time = current_time
    if scanning:
        scan_progress += 0.01
        if scan_progress >= 1:
            scan_progress = 0
    screen.fill(BLACK)
    for x in range(0, WIDTH, 20):
        pygame.draw.line(screen, (20, 20, 30), (x, 0), (x, HEIGHT), 1)
    for y in range(0, HEIGHT, 20):
        pygame.draw.line(screen, (20, 20, 30), (0, y), (WIDTH, y), 1)
    draw_ui()
    update_particles()
    draw_particles()
    draw_core()
    
    pygame.display.flip()
    
    clock.tick(60)

pygame.quit()
