# Importamos logging
import logging
from config import BOT_TOKEN
from bot_handlers import start, handle_message
from telegram.ext import Application, CommandHandler, MessageHandler, filters
from telegram.request import HTTPXRequest
from bot_handlers import start, handle_message, help_command, about_command, button_handler
from telegram.ext import CallbackQueryHandler
from telegram import BotCommand

# Configurar logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.DEBUG  # Cambiar a INFO para menos verbosidad en producción
)

def main():
    """
    Configura y ejecuta el bot en modo polling.
    """
    logging.info("Iniciando el bot...")

    # Configura una solicitud HTTP personalizada con timeout
    request = HTTPXRequest(connect_timeout=12.0, read_timeout=30.0)

    # Configura la aplicación del bot con la configuración personalizada
    application = Application.builder().token(BOT_TOKEN).request(request).build()

    # Establecemos comandos sugeridos al abrir el bot
    application.bot.set_my_commands([
        BotCommand("start", "Inicia el bot y muestra opciones"),
        BotCommand("help", "Muestra una lista de comandos disponibles"),
        BotCommand("about", "Proporciona información sobre el bot")
    ])

    # Registramos los manejadores del bot
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))  
    application.add_handler(CommandHandler("about", about_command))  
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(CallbackQueryHandler(button_handler))

    # Ejecuta el bot usando `run_polling`
    logging.info("Bot iniciado. Presiona Ctrl+C para detenerlo.")
    application.run_polling()

if __name__ == '__main__':
    main()
