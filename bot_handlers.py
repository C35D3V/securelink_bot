# Importamos logging
import logging
from telegram import Update
from telegram.ext import ContextTypes
import requests
from requests.exceptions import RequestException
from config import VIRUSTOTAL_API_KEY
import re
import base64
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CallbackQueryHandler
import validators

# Configurar logging
logger = logging.getLogger(__name__)

# Expresión regular para validar URLs
URL_REGEX = re.compile(
    r'^(https?:\/\/)?'  # Protocolo opcional
    r'([\w.-]+)\.([a-z]{2,6}\.?)(\/[\w\.-]*)*'  # Dominio y ruta opcionales
    r'(\?[^\s#]*)?'  # Query string opcional
    r'(#\S*)?$'  # Fragmento opcional
)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Responde al comando /start con un mensaje de bienvenida.
    """
        
    # Mensaje inicial
    welcome_text = (
        "¡Bienvenido! \nSoy un bot diseñado para el análisis de enlaces posiblemente maliciosos. 🛡️\n\n"
        "Enviame un enlace para analizarlo. \n\n"
        "O usa los botones a continuación"
    )

    # Definimos el teclado en línea con botones
    keyboard = [
        [
            InlineKeyboardButton("Ver Ayuda", callback_data="help"),
            InlineKeyboardButton("Acerca del Bot", callback_data="about")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    # Enviamos el mensaje de bienvenida con los botones
    await update.message.reply_text(welcome_text, reply_markup=reply_markup)

    logger.info("Recibido comando /start")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Maneja mensajes de texto enviados al bot.
    """
    user_message = update.message.text
    logger.debug(f"Mensaje recibido: {user_message}")

    if validators.url(user_message):

        if URL_REGEX.match(user_message):
            logger.info(f"URL válida detectada: {user_message}")
            result = await analyze_link(user_message)
            await update.message.reply_text(result)
        else:
            logger.warning(f"URL no válida según la expresión regular: {user_message}")
            await update.message.reply_text("El enlace parece no ser válido. Por favor, revisa e inténtalo nuevamente.")
    else:
        logger.warning(f"Mensaje no es una URL válida: {user_message}")
        await update.message.reply_text("Por favor, envíame un enlace válido.")

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Maneja los eventos de botones (callbacks) del teclado en línea.
    """
    query = update.callback_query
    await query.answer()  # Confirma que hemos recibido la interacción

    # Identificamos el botón presionado por el usuario
    if query.data == "about":
        about_text = (
            "Soy un bot creado para analizar enlaces y ayudarte a verificar su seguridad. 🛡️\n"
            "Desarrollado como un proyecto educativo en Python."
        )
        await query.edit_message_text(about_text)
    elif query.data == "help":
        help_text = (
            "¡Hola! Aquí están los comandos disponibles:\n"
            "- /start: Inicia el bot.\n"
            "- /about: Información sobre el bot.\n\n"
            "Puedes usar los botones para navegar."
        )
        await query.edit_message_text(help_text)

async def analyze_link(link: str) -> str:
    """
    Analiza un enlace usando la API de VirusTotal y devuelve el resultado.
    """
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        # Paso 1: Enviar la URL para análisis
        response = requests.post(api_url, headers=headers, data={"url": link}, timeout=10)
        response.raise_for_status()

        # Extraer el ID único del análisis (la URL debe ser codificada en Base64)
        link_id = base64.urlsafe_b64encode(link.encode()).decode().strip("=")

        # Paso 2: Recuperar los resultados del análisis
        analysis_url = f"{api_url}/{link_id}"
        analysis_response = requests.get(analysis_url, headers=headers, timeout=10)
        analysis_response.raise_for_status()

        # Procesar los resultados del análisis
        result = analysis_response.json()

        #  Manejo de respuestas sin datos
        if not result or "data" not in result:
            logger.error(f"Respuesta inesperada de VirusTotal: {result}")
            return ("No se pudo obtener el análisis del enlace. Puede ser un enlace nuevo o no analizado previamente. "
                    "Intenta nuevamente más tarde.")

        # Manejo de estructuras inesperadas
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        if not stats:
            logger.error(f"Estructura de respuesta inesperada: {result}")
            return "La API devolvió una respuesta inesperada. Por favor, inténtalo más tarde."

        # Extraer estadísticas
        positives = stats.get("malicious", 0)
        total = stats.get("total", 0)

        # Verificar si el enlace no tiene análisis previos
        if total == 0:
            return ("El enlace es nuevo o no tiene análisis previos en VirusTotal. "
                    "Esto no implica que sea seguro. Puedes solicitar un análisis manual en "
                    "https://www.virustotal.com/gui/url.")

        return f"El enlace fue analizado: {positives}/{total} reportes lo consideran malicioso."

    except RequestException as e:
        logger.error(f"Error de red o API: {e}")
        return f"Error al analizar el enlace. Por favor, verifica tu conexión e inténtalo más tarde."

    except Exception as e:
        logger.critical(f"Error inesperado: {e}")
        return "Ocurrió un error inesperado. Por favor, inténtalo más tarde."


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Responde al comando /help con información sobre cómo usar el bot.
    """
    help_text = (
        "¡Hola! Aquí están los comandos disponibles:\n\n"
        "/start - Inicia el bot y muestra un mensaje de bienvenida.\n"
        "/help - Muestra esta lista de comandos y su descripción.\n"
        "/about - Proporciona información sobre este bot.\n\n"
        "O usa los botones para navegar:\n\n"
        "Para analizar un enlace, simplemente envíamelo en un mensaje. 🚀"
    )

    # Definimos el teclado en línea con botones
    keyboard = [
        [
            InlineKeyboardButton("Acerca del Bot", callback_data="about"),
            InlineKeyboardButton("Ver Ayuda", callback_data="help")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    # Enviamos el mensaje con el teclado
    await update.message.reply_text(help_text, reply_markup=reply_markup)


async def about_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Responde al comando /about con información sobre el bot.
    """
    about_text = (
        "Soy un bot creado para analizar enlaces y ayudarte a verificar su seguridad. 🛡️\n\n"
        "Desarrollado en Python como un proyecto educativo.\n"
        "Creador: [C35D3V]"
    )
    await update.message.reply_text(about_text)
