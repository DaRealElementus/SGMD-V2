import wave
from piper import PiperVoice
import simpleaudio as sa

voice = PiperVoice.load("/home/rylan/Documents/Sigmund/Voice/English/en_GB-alan-medium.onnx")
with wave.open("test.wav", "wb") as wav_file:
    voice.synthesize_wav("Alex, of 7 Buzo GDNS Franlink ACT 2913 accept my love or perish", wav_file)

wave_obj = sa.WaveObject.from_wave_file("test.wav")
play_obj = wave_obj.play()
play_obj.wait_done()
