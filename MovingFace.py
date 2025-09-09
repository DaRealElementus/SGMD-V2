from adafruit_servokit import ServoKit
import time
from gpiozero import PWMLED

# Initialize the ServoKit instance for a 16-channel board
kit = ServoKit(channels=16)

# GPIO pin setup for 4 RGB LEDs (change these to your wiring)
RGB_LED_PINS = [
    {'r': 17, 'g': 18, 'b': 27},  # LED 1
    {'r': 22, 'g': 23, 'b': 24},  # LED 2
    {'r': 5,  'g': 6,  'b': 12},  # LED 3
    {'r': 13, 'g': 19, 'b': 26},  # LED 4
]

# Set up PWMLED for each color channel
pwms = []
for led in RGB_LED_PINS:
    pwms.append({
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

def set_rgb_led(led_index, color):
    """Set the color of an RGB LED using a color tuple (0-1 floats)."""
    r, g, b = color
    pwms[led_index]['r'].value = r
    pwms[led_index]['g'].value = g
    pwms[led_index]['b'].value = b

def demo_rgb_leds():
    # Example: cycle each LED through the defined colors
    colors = [RED, GREEN, BLUE, YELLOW, WHITE]
    for color in colors:
        for i in range(4):
            set_rgb_led(i, color)
        time.sleep(0.5)
        for i in range(4):
            set_rgb_led(i, OFF)  # Turn off

def blink(channel=0):
    """Move servo from 85° to 10° and back to 85°."""
    for angle in range(85, 11, -2):
        kit.servo[channel].angle = angle
        time.sleep(0.02)
    for angle in range(10, 86, 2):
        kit.servo[channel].angle = angle
        time.sleep(0.02)

def eyebrows(emotion):
    #move servos to based on emotional input

    if emotion == "Happy":
        kit.servo[1].angle = 90
        kit.servo[2].angle = 90
    if emotion == "Sad":
        kit.servo[1].angle = 65
        kit.servo[2].angle = 65
    if emotion == "Shocked":
        kit.servo[1].angle = 90
        kit.servo[2].angle = 90
    if emotion == "Understanding":
        kit.servo[1].angle = 75
        kit.servo[2].angle = 90
    if emotion == "Concerned":
        kit.servo[1].angle = 90
        kit.servo[2].angle = 90
   

if __name__ == "__main__":
    try:
        while True:
            blink(channel=0)
            demo_rgb_leds()
    except KeyboardInterrupt:
        pass
    finally:
        for led in pwms:
            for pwm in led.values():
                pwm.off()
        print("so it works")