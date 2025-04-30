import os
import base64

OUTPUT_PATH = os.getenv("LOOKER_KEY_PATH", "tools/sync/looker-key.json")
KEY_B64 = os.getenv("LOOKER_KEY_B64")

if not KEY_B64:
    raise ValueError("❌ LOOKER_KEY_B64 no está configurado en los Secrets de GitHub Actions.")

try:
    decoded = base64.b64decode(KEY_B64).decode("utf-8")

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        f.write(decoded)
    print(f"✅ Clave de servicio decodificada en: {OUTPUT_PATH}")
except Exception as e:
    raise RuntimeError(f"❌ Error al decodificar y guardar el archivo: {e}")
