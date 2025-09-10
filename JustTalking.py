import wave
from piper import PiperVoice
import simpleaudio as sa
import os

voice_file = "en_GB-alan-medium.onnx"

voice = PiperVoice.load(os.path.join("Voices", "English", voice_file))
with wave.open("test.wav", "wb") as wav_file:
    voice.synthesize_wav("Hi! I'm Sigmund a local AI therapist, here to talk and aid you with any and every problem you may have.", wav_file)

wave_obj = sa.WaveObject.from_wave_file("test.wav")
play_obj = wave_obj.play()
play_obj.wait_done()
