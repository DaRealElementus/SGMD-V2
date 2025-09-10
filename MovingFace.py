from adafruit_servokit import ServoKit
import time
from gpiozero import PWMLED

# Initialize the ServoKit instance for a 16-channel board
kit = ServoKit(channels=16)

# GPIO pin setup for 2 RGB LEDs (change these to your wiring)
EYE_RGB_LED_PINS = [
    {'r': 17, 'g': 18, 'b': 27},  # Eye LED



]
CHEEK_RGB_LED_PINS = [
    {'r': 22, 'g': 23, 'b': 24},  # Cheek LED
]

# Set up PWMLED for each color channel for eyes and cheeks
eye_pwms = []
for led in EYE_RGB_LED_PINS:
    eye_pwms.append({
        'r': PWMLED(led['r']),
        'g': PWMLED(led['g']),
        'b': PWMLED(led['b'])
    })

cheek_pwms = []
for led in CHEEK_RGB_LED_PINS:
    cheek_pwms.append({

        'r': PWMLED(led['r']),
        'g': PWMLED(led['g']),
        'b': PWMLED(led['b'])
    })

# Color definitions (0-1 for each channel)
RED    = (1, 0, 0)
GREEN  = (0, 1, 0)
BLUE   = (0, 0, 1)
YELLOW = (1, 1, 0)
WHITE  = (1, 1, 1)
OFF    = (0, 0, 0)

def set_rgb_led(led_index, color, group='eye'):
    """Set the color of an RGB LED in the specified group ('eye' or 'cheek')."""
    r, g, b = color
    if group == 'eye':
        pwms = eye_pwms
    elif group == 'cheek':
        pwms = cheek_pwms
    else:
        raise ValueError("Invalid group. Use 'eye' or 'cheek'.")
    pwms[led_index]['r'].value = r
    pwms[led_index]['g'].value = g
    pwms[led_index]['b'].value = b

def set_eyes_color(color):
    """Set all eye LEDs to the specified color."""
    for i in range(len(eye_pwms)):
        set_rgb_led(i, color, group='eye')

def set_cheeks_color(color):
    """Set all cheek LEDs to the specified color."""
    for i in range(len(cheek_pwms)):
        set_rgb_led(i, color, group='cheek')

def blink(channel=0):
    """Move servo from 85° to 10° and back to 85°."""
    for angle in range(85, 11, -2):
        kit.servo[channel].angle = angle
        time.sleep(0.02)
    for angle in range(10, 86, 2):
        kit.servo[channel].angle = angle
        time.sleep(0.02)

def happy_face(emotion):


    if emotion == "Happy":
        kit.servo[1].angle = 90
        kit.servo[2].angle = 90
        set_cheeks_color(YELLOW)

def sad_face(emotion):
    if emotion == "Sad":
        kit.servo[1].angle = 65
        kit.servo[2].angle = 65
        set_cheeks_color(BLUE)

def shocked_face(emotion):
    if emotion == "Shocked":
        kit.servo[1].angle = 90
        kit.servo[2].angle = 90
        set_cheeks_color(WHITE)

def understanding_face(emotion):
    if emotion == "Understanding":
        kit.servo[1].angle = 75
        kit.servo[2].angle = 90
        set_cheeks_color(GREEN)

def concerned_face(emotion):
    if emotion == "Concerned":
        kit.servo[1].angle = 90
        kit.servo[2].angle = 90
        set_cheeks_color(RED)

if __name__ == "__main__":
    try:
        set_eyes_color(BLUE)
        while True:
            blink(channel=0)

    except KeyboardInterrupt:
        pass
    finally:
        for led in eye_pwms + cheek_pwms:
            for pwm in led.values():
                pwm.off()
        print("so it works")