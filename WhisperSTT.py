import sounddevice as sd
import noisereduce as nr
import numpy as np
import soundfile as sf
from faster_whisper import WhisperModel
import os

model = WhisperModel("base.en", compute_type='int8')
vad = webrtcvad.Vad(2)
samplerate = 16000
frame_duration = 30
frame_size = int(samplerate * frame_duration / 1000)

audio_q = queue.Queue()

def audio_callback(indata, frames, time, status):
    if status:
        print(status)
    audio_q.put(bytes(indata))

def is_speech(audio_bytes):
    return vad.is_speech(audio_bytes, samplerate)

def start_streaming(callback):
    stream = sd.RawInputStream(samplerate=samplerate, blocksize=frame_size, dtype='int16', channels=1, callback=audio_callback)
    stream.start()

    buffer = b''
    speaking = False

    while True:
        data = audio_q.get()
        if is_speech(data):
            buffer += data
            speaking = True
        elif speaking:
            audio_np = np.frombuffer(buffer, dtype=np.int16).astype(np.float32) / 32768.0
            sf.write("speech.wav", audio_np, samplerate)
            segments, _ = model.transcribe("speech.wav")
            full_text = " ".join([seg.text.strip() for seg in segments])
            callback(full_text)
            buffer = b''
            speaking = False
        print(full_text)