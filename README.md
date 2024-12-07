# SecureLink Bot
SecureLink Bot es un bot de Telegram diseñado para analizar enlaces y ayudar a los usuarios a identificar posibles amenazas de seguridad. 🛡️

## Características

- Analiza enlaces utilizando la API de [VirusTotal](https://www.virustotal.com).
- Valida y formatea enlaces antes de enviarlos para análisis.
- Ofrece un teclado interactivo con botones para navegar entre opciones.
- Respuestas enriquecidas usando formato MarkdownV2 para mensajes claros y atractivos.

## Requisitos

- Python 3.9 o superior
- Token de la API de Telegram (creado con [BotFather](https://core.telegram.org/bots#botfather))
- API Key de VirusTotal

## Instalación

_Clona este repositorio:_
   ```bash
   git clone https://github.com/C35D3V/securelink_bot.git
   cd securelink_bot
   ```

## Configura un entorno virtual
```bash
python -m venv env

source env/bin/activate  

#En Windows usa 

.\env\Scripts\activate
```

## Instala las dependencias
```bash
pip install -r requirements.txt
```

## Crea un archivo .env con tus claves:
```bash
TELEGRAM_BOT_TOKEN=tu_telegram_bot_token
VIRUSTOTAL_API_KEY=tu_virustotal_api_key
```

## Ejecuta el Bot
```bash
python main.py
```

## Uso
- Usa el comando */start* para iniciar el bot.
- Envía un enlace para analizarlo.
- Usa */help* para ver los comandos disponibles.

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue o envía un pull request para cualquier sugerencia o mejora.

## Comentarios de este proyecto.

Este bot es basico y sirve de partida para agregar muchas nuevas funciones, *se ha creado como proyecto de estudio*
