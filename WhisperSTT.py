import sounddevice as sd
import numpy as np
import soundfile as sf
from faster_whisper import WhisperModel
import sys
from pynput import keyboard

# --- CONFIGURATION ---
MODEL_SIZE = "base.en"
COMPUTE_TYPE = "int8"
SAMPLERATE = 44100
CHANNELS = 1
INPUT_DEVICE_INDEX = 0  # Set to your mic device index, or None for default

# --- INITIALIZATION ---
model = WhisperModel(MODEL_SIZE, compute_type=COMPUTE_TYPE)

class Recorder:
    def __init__(self, samplerate, channels, device_index=None):
        self.samplerate = samplerate
        self.channels = channels
        self.device_index = device_index
        self.buffer = []
        self.stream = None
        self.recording = False

    def callback(self, indata, frames, time, status):
        if status:
            print("Audio status:", status, file=sys.stderr)
        if self.recording:
            self.buffer.append(indata.copy())

    def start(self):
        self.buffer = []
        self.recording = True
        if self.device_index is not None:
            sd.default.device = (self.device_index, None)
        self.stream = sd.InputStream(
            samplerate=self.samplerate,
            channels=self.channels,
            dtype='int16',
            callback=self.callback
        )
        self.stream.start()
        print("Recording started...")

    def stop(self):
        self.recording = False
        if self.stream is not None:
            self.stream.stop()
            self.stream.close()
            self.stream = None
        if not self.buffer:
            print("Warning: No audio was recorded.")
            return np.array([], dtype=np.int16)
        audio_np = np.concatenate(self.buffer, axis=0).flatten()
        print(f"Recording stopped. {len(audio_np)} samples captured.")
        return audio_np

def print_input_device_info():
    devices = sd.query_devices()
    if INPUT_DEVICE_INDEX is not None:
        try:
            device_info = devices[INPUT_DEVICE_INDEX]
            print(f"Using input device {INPUT_DEVICE_INDEX}: {device_info['name']} (default_samplerate={device_info['default_samplerate']})")
        except Exception as e:
            print(f"Could not get info for device {INPUT_DEVICE_INDEX}: {e}")
    else:
        print("Using default input device.")
        print(sd.query_devices(sd.default.device[0]))

def transcribe_audio(audio_np):
    if audio_np.size == 0:
        return "[No audio to transcribe]"
    sf.write("speech.wav", audio_np.astype(np.float32) / 32768.0, SAMPLERATE)
    print("Saved speech.wav")
    segments, _ = model.transcribe("speech.wav")
    return " ".join([seg.text.strip() for seg in segments])

def main():
    print_input_device_info()
    print("Hold SPACE to record. Release to transcribe. (Ctrl+C to exit)")
    recorder = Recorder(SAMPLERATE, CHANNELS, INPUT_DEVICE_INDEX)

    def on_press(key):
        if key == keyboard.Key.space and not recorder.recording:
            recorder.start()

    def on_release(key):
        if key == keyboard.Key.space and recorder.recording:
            audio_np = recorder.stop()
            print("Transcribing...")
            text = transcribe_audio(audio_np)
            print("Recognized:", text)
            return False  # Stop listener

    while True:
        print("Waiting for SPACE...")
        with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
