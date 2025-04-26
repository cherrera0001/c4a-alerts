import os
import logging
import re
from typing import Dict

# Tratar de importar SentenceTransformer (modelo local)
try:
    from sentence_transformers import SentenceTransformer, util
    NLP_AVAILABLE = True
except ImportError:
    NLP_AVAILABLE = False

# Configuración de entorno
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ENABLE_OPENAI = os.getenv("ENABLE_OPENAI", "false").lower() == "true"
OPENAI_AVAILABLE = False

# Tratar de importar OpenAI
try:
    if ENABLE_OPENAI and OPENAI_API_KEY:
        import openai
        openai.api_key = OPENAI_API_KEY
        OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

# Inicializar modelo local si está disponible
if NLP_AVAILABLE:
    try:
        model = SentenceTransformer('all-MiniLM-L6-v2')
    except Exception as e:
        logging.error(f"❌ Error loading local NLP model: {e}")
        NLP_AVAILABLE = False


def clean_text(text: str) -> str:
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def summarize_with_openai(alert: Dict) -> Dict:
    """
    Usa OpenAI para resumir alertas.
    """
    prompt = f"""
Resume la siguiente alerta de seguridad en 2 a 3 líneas, destacando los aspectos críticos:

Título: {alert.get('title', '')}
Resumen: {alert.get('summary', '')}
URL: {alert.get('url', '')}

Respuesta:
"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Eres un analista de ciberseguridad experto."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=200
        )
        summary = response['choices'][0]['message']['content'].strip()
        alert['summary'] = summary
    except Exception as e:
        logging.error(f"❌ OpenAI summarization failed: {e}")
    return alert


def summarize_locally(alert: Dict) -> Dict:
    """
    Usa modelo local para intentar resumir.
    """
    if not NLP_AVAILABLE:
        return alert

    title = alert.get('title', '')
    summary = alert.get('summary', '')

    try:
        # Combinar título y resumen
        text = clean_text(f"{title}. {summary}")

        # Embedding y simple truncamiento
        embedding = model.encode(text, convert_to_tensor=True)
        if len(text.split()) > 50:
            sentences = text.split('.')
            summary_sentences = '. '.join(sentences[:2])
            alert['summary'] = summary_sentences
    except Exception as e:
        logging.error(f"❌ Local summarization failed: {e}")

    return alert


def process_alert(alert: Dict) -> Dict:
    """
    Procesa y resume una alerta si el procesamiento NLP está disponible.
    """
    if not NLP_AVAILABLE and not (ENABLE_OPENAI and OPENAI_AVAILABLE):
        return alert

    try:
        if ENABLE_OPENAI and OPENAI_AVAILABLE:
            summarized_alert = summarize_with_openai(alert)
        else:
            summarized_alert = summarize_locally(alert)
        return summarized_alert
    except Exception as e:
        logging.error(f"❌ Error processing alert: {e}")
        return alert
