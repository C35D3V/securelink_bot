import os
from dotenv import load_dotenv

# 🚨 Línea para cargar las variables de entorno
load_dotenv()

# 🚨 Línea para definir el token como variable global
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

if not BOT_TOKEN:
    raise ValueError("El token del bot no está configurado. Usa una variable de entorno TELEGRAM_BOT_TOKEN.")

# 🚨 Añadimos la línea para cargar la clave de VirusTotal
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    raise ValueError("La clave de la API de VirusTotal no está configurada. Usa una variable de entorno VIRUSTOTAL_API_KEY.")
