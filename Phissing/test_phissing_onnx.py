"""
Test Script untuk Phishing Detection ONNX Model
================================================
Cara pakai:
    pip install onnxruntime numpy
    python test_phishing_onnx.py

Catatan: Karena tokenizer tidak disimpan dari Kaggle,
script ini menggunakan simple word-index tokenizer
yang mereplikasi logika Keras Tokenizer.
Untuk hasil akurat, export tokenizer dari Kaggle (lihat bagian bawah).
"""

import numpy as np
import re
import string

# ─────────────────────────────────────────
# KONFIGURASI (harus sama dengan training)
# ─────────────────────────────────────────
ONNX_PATH   = "phishing_model.onnx"  # ganti path jika perlu
MAX_LEN     = 300
MAX_WORDS   = 10000
OOV_TOKEN   = "<OOV>"

# ─────────────────────────────────────────
# CEK & LOAD MODEL ONNX
# ─────────────────────────────────────────
try:
    import onnxruntime as ort
    print("✅ onnxruntime tersedia")
except ImportError:
    print("❌ onnxruntime belum terinstall. Jalankan: pip install onnxruntime")
    exit(1)

try:
    session = ort.InferenceSession(ONNX_PATH)
    print(f"✅ Model berhasil dimuat: {ONNX_PATH}")
except Exception as e:
    print(f"❌ Gagal load model: {e}")
    exit(1)

# Info model
input_info  = session.get_inputs()[0]
output_info = session.get_outputs()[0]
print(f"\n📋 Model Info:")
print(f"   Input  : name='{input_info.name}', shape={input_info.shape}, dtype={input_info.type}")
print(f"   Output : name='{output_info.name}', shape={output_info.shape}, dtype={output_info.type}")

# ─────────────────────────────────────────
# PREPROCESSING
# ─────────────────────────────────────────
def clean_text(text: str) -> str:
    """Bersihkan teks seperti di notebook training."""
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', '', text)          # hapus URL
    text = re.sub(r'\S+@\S+', '', text)                  # hapus email
    text = re.sub(r'[^a-z\s]', '', text)                 # hapus non-huruf
    text = re.sub(r'\s+', ' ', text).strip()             # normalisasi spasi
    return text


class SimpleTokenizer:
    """
    Tokenizer sederhana yang mereplikasi Keras Tokenizer.
    
    PENTING: Ini hanya untuk testing dasar.
    Untuk hasil yang sama persis dengan training, gunakan tokenizer
    yang disimpan dari Kaggle (lihat instruksi di bawah).
    """
    def __init__(self):
        self.word_index = {}    # word → index
        self.fitted = False

    def fit(self, texts):
        from collections import Counter
        all_words = []
        for t in texts:
            all_words.extend(clean_text(t).split())
        counts = Counter(all_words)
        # Urutkan by frequency (sama seperti Keras Tokenizer)
        sorted_words = [w for w, _ in counts.most_common(MAX_WORDS - 1)]
        self.word_index = {w: i+2 for i, w in enumerate(sorted_words)}
        self.word_index[OOV_TOKEN] = 1
        self.fitted = True
        print(f"✅ Tokenizer fitted: {len(self.word_index)} kata")

    def texts_to_sequences(self, texts):
        seqs = []
        for t in texts:
            words = clean_text(t).split()
            seq = [self.word_index.get(w, 1) for w in words]  # 1 = OOV
            seqs.append(seq)
        return seqs


def pad_sequence(seq, maxlen=MAX_LEN):
    """Padding/truncate ke MAX_LEN (post-padding)."""
    if len(seq) > maxlen:
        seq = seq[:maxlen]
    else:
        seq = seq + [0] * (maxlen - len(seq))
    return seq


# ─────────────────────────────────────────
# FUNGSI PREDIKSI
# ─────────────────────────────────────────
tokenizer = SimpleTokenizer()

def predict(text: str, tok=None) -> dict:
    """
    Prediksi apakah email adalah phishing atau safe.
    
    Args:
        text: isi email
        tok : tokenizer (SimpleTokenizer atau Keras Tokenizer)
    
    Returns:
        dict dengan keys: label, confidence, raw_score
    """
    if tok is None:
        tok = tokenizer

    cleaned = clean_text(text)
    seq     = tok.texts_to_sequences([cleaned])[0]
    padded  = np.array([pad_sequence(seq)], dtype=np.float32)

    input_name = session.get_inputs()[0].name
    result     = session.run(None, {input_name: padded})
    score      = float(result[0][0][0])

    label = "🚨 PHISHING" if score > 0.5 else "✅ SAFE"
    return {
        "label"      : label,
        "confidence" : f"{score*100:.1f}%" if score > 0.5 else f"{(1-score)*100:.1f}%",
        "raw_score"  : round(score, 4),
    }


# ─────────────────────────────────────────
# CONTOH EMAIL UNTUK TEST
# ─────────────────────────────────────────
test_emails = [
    {
        "desc": "Phishing klasik (bank palsu)",
        "text": (
            "URGENT: Your bank account has been suspended. "
            "Click here immediately to verify your identity and avoid account closure. "
            "Login now at http://secure-bank-verify.com/login with your credentials."
        )
    },
    {
        "desc": "Phishing hadiah palsu",
        "text": (
            "Congratulations! You have been selected as a winner of $1,000,000 lottery prize. "
            "To claim your prize, send us your personal details, bank account number, and a processing fee of $50."
        )
    },
    {
        "desc": "Email kantor normal (safe)",
        "text": (
            "Hi team, please find attached the agenda for tomorrow's meeting at 10am. "
            "We will discuss Q3 results and planning for next quarter. Let me know if you have any questions."
        )
    },
    {
        "desc": "Email teknis normal (safe)",
        "text": (
            "The deployment pipeline for version 2.3.1 has completed successfully. "
            "All unit tests passed. The new features are now live in the production environment."
        )
    },
    {
        "desc": "Phishing password reset palsu",
        "text": (
            "Your password will expire in 24 hours. Click the link below to reset your password immediately "
            "or your account will be permanently deleted. Act now to secure your account."
        )
    },
]

# ─────────────────────────────────────────
# JALANKAN TEST
# (tokenizer fit dari contoh di atas dulu,
#  hanya untuk uji pipeline — bukan akurasi sebenarnya)
# ─────────────────────────────────────────
import json

# Load tokenizer dari JSON (tidak butuh keras/tensorflow)
with open('tokenizer_word_index.json', 'r') as f:
    word_index = json.load(f)

print(f"✅ Tokenizer dimuat: {len(word_index)} kata")

class JSONTokenizer:
    def __init__(self, word_index, max_words=20000):
        self.word_index = word_index
        self.max_words = max_words

    def texts_to_sequences(self, texts):
        seqs = []
        for t in texts:
            words = clean_text(t).split()
            seq = []
            for w in words:
                idx = self.word_index.get(w, 1)  # 1 = OOV
                # Clip index supaya tidak melebihi MAX_WORDS
                if idx >= self.max_words:
                    idx = 1  # treat sebagai OOV
                seq.append(idx)
            seqs.append(seq)
        return seqs

keras_tok = JSONTokenizer(word_index, max_words=20000)

print("\n" + "="*60)
print("  TEST PIPELINE ONNX (dengan tokenizer asli)")
print("="*60)

for i, item in enumerate(test_emails, 1):
    result = predict(item["text"], tok=keras_tok)
    print(f"[{i}] {item['desc']}")
    print(f"     Prediksi  : {result['label']}")
    print(f"     Confidence: {result['confidence']}")
    print(f"     Raw score : {result['raw_score']}")
    print()
# ─────────────────────────────────────────
# INSTRUKSI: PAKAI TOKENIZER ASLI DARI KAGGLE
# ─────────────────────────────────────────
#print("="*60)
#print("  CARA PAKAI TOKENIZER ASLI (Rekomendasi)")
#print("="*60)
print("""
1. Di Kaggle, tambahkan cell ini SETELAH training selesai:

   import pickle
   with open('/kaggle/working/tokenizer.pkl', 'wb') as f:
       pickle.dump(tokenizer, f)

2. Download tokenizer.pkl dari panel Output Kaggle.

3. Letakkan tokenizer.pkl satu folder dengan script ini,
   lalu ganti bagian bawah script ini dengan:

   import pickle
   with open('tokenizer.pkl', 'rb') as f:
       keras_tok = pickle.load(f)

   # Lalu panggil predict dengan tokenizer asli:
   result = predict(email_text, tok=keras_tok)
""")