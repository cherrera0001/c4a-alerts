import os
import logging
import json
from typing import Dict, Any, List, Optional
import requests
from sentence_transformers import SentenceTransformer
import numpy as np

# Check if OpenAI API key is available
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_AVAILABLE = bool(OPENAI_API_KEY)

# Initialize sentence transformer model for semantic matching
try:
    # Use a smaller model for GitHub Actions compatibility
    model = SentenceTransformer('all-MiniLM-L6-v2')
    SENTENCE_TRANSFORMER_AVAILABLE = True
except Exception as e:
    logging.warning(f"⚠️ Sentence Transformer not available: {e}")
    SENTENCE_TRANSFORMER_AVAILABLE = False

# Attack types and techniques for classification
ATTACK_TYPES = [
    "Remote Code Execution", "SQL Injection", "Cross-Site Scripting", 
    "Denial of Service", "Authentication Bypass", "Information Disclosure",
    "Privilege Escalation", "Command Injection", "Memory Corruption",
    "Path Traversal", "Supply Chain Attack", "Zero-Day Exploit"
]

# Tech stacks for classification
TECH_STACKS = [
    "Windows", "Linux", "macOS", "Android", "iOS", 
    "AWS", "Azure", "GCP", "Docker", "Kubernetes",
    "Node.js", "Python", "Java", "PHP", "Ruby",
    "Apache", "Nginx", "IIS", "WordPress", "Drupal"
]

def summarize_with_openai(text: str, max_tokens: int = 150) -> Optional[str]:
    """
    Summarize text using OpenAI's API.
    """
    if not OPENAI_AVAILABLE:
        return None
        
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }
        
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity analyst. Summarize the following security alert concisely."},
                {"role": "user", "content": text}
            ],
            "max_tokens": max_tokens,
            "temperature": 0.3
        }
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()
        else:
            logging.error(f"❌ OpenAI API error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logging.error(f"❌ Error using OpenAI API: {e}")
        return None

def classify_threat(text: str) -> Dict[str, Any]:
    """
    Classify threat by attack type and affected tech stack using sentence transformers.
    """
    if not SENTENCE_TRANSFORMER_AVAILABLE:
        return {"attack_types": [], "tech_stacks": [], "confidence": 0.0}
        
    try:
        # Encode the input text
        text_embedding = model.encode(text)
        
        # Encode attack types and tech stacks
        attack_embeddings = model.encode(ATTACK_TYPES)
        tech_embeddings = model.encode(TECH_STACKS)
        
        # Calculate cosine similarity
        attack_similarities = np.dot(attack_embeddings, text_embedding) / (
            np.linalg.norm(attack_embeddings, axis=1) * np.linalg.norm(text_embedding)
        )
        
        tech_similarities = np.dot(tech_embeddings, text_embedding) / (
            np.linalg.norm(tech_embeddings, axis=1) * np.linalg.norm(text_embedding)
        )
        
        # Get top matches with threshold
        attack_threshold = 0.45
        tech_threshold = 0.40
        
        top_attacks = [ATTACK_TYPES[i] for i, score in enumerate(attack_similarities) if score > attack_threshold]
        top_techs = [TECH_STACKS[i] for i, score in enumerate(tech_similarities) if score > tech_threshold]
        
        # Calculate overall confidence
        if top_attacks or top_techs:
            max_confidence = max(
                max(attack_similarities) if len(attack_similarities) > 0 else 0,
                max(tech_similarities) if len(tech_similarities) > 0 else 0
            )
        else:
            max_confidence = 0.0
            
        return {
            "attack_types": top_attacks,
            "tech_stacks": top_techs,
            "confidence": float(max_confidence)
        }
        
    except Exception as e:
        logging.error(f"❌ Error classifying threat: {e}")
        return {"attack_types": [], "tech_stacks": [], "confidence": 0.0}

def process_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process an alert with NLP to add summary and classification.
    """
    # Combine title and summary for processing
    text_to_process = f"{alert.get('title', '')} {alert.get('summary', '')}"
    
    # Add summary if OpenAI is available
    if OPENAI_AVAILABLE:
        summary = summarize_with_openai(text_to_process)
        if summary:
            alert["ai_summary"] = summary
    
    # Add classification
    classification = classify_threat(text_to_process)
    alert["classification"] = classification
    
    return alert
