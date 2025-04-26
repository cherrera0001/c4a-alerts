import os
import logging

# Intentar importar SentenceTransformer de sentence-transformers
try:
    from sentence_transformers import SentenceTransformer, util
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logging.warning("⚠️ sentence-transformers library not found. NLP features disabled.")

# Variables de control de NLP y OpenAI
ENABLE_OPENAI = os.getenv("ENABLE_OPENAI", "false").lower() == "true"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_AVAILABLE = bool(ENABLE_OPENAI and OPENAI_API_KEY)

# Si está disponible sentence-transformers, cargar modelo
if SENTENCE_TRANSFORMERS_AVAILABLE:
    try:
        model = SentenceTransformer("all-MiniLM-L6-v2")
    except Exception as e:
        logging.error(f"❌ Error loading SentenceTransformer model: {e}")
        model = None
        SENTENCE_TRANSFORMERS_AVAILABLE = False

if OPENAI_AVAILABLE:
    try:
        import openai
        openai.api_key = OPENAI_API_KEY
    except Exception as e:
        logging.error(f"❌ Error initializing OpenAI: {e}")
        OPENAI_AVAILABLE = False


def summarize_text(text: str) -> str:
    """Genera un resumen usando OpenAI si está disponible."""
    if not OPENAI_AVAILABLE:
        return text

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Resume el siguiente texto en español de manera concisa y técnica."},
                {"role": "user", "content": text}
            ],
            temperature=0.2,
            max_tokens=150
        )
        summary = response["choices"][0]["message"]["content"].strip()
        return summary
    except Exception as e:
        logging.error(f"❌ OpenAI summarization error: {e}")
        return text


def are_texts_similar(text1: str, text2: str, threshold: float = 0.8) -> bool:
    """Evalúa la similitud entre dos textos usando embeddings."""
    if not SENTENCE_TRANSFORMERS_AVAILABLE or model is None:
        logging.warning("⚠️ Text similarity check skipped: sentence-transformers not available.")
        return False

    try:
        emb1 = model.encode(text1, convert_to_tensor=True)
        emb2 = model.encode(text2, convert_to_tensor=True)
        similarity = util.cos_sim(emb1, emb2).item()
        return similarity >= threshold
    except Exception as e:
        logging.error(f"❌ Error during text similarity calculation: {e}")
        return False
