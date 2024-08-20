import requests

CHAT_ID = '584066666'
TELEGRAMBOT_URL = "https://api.telegram.org/bot{}/sendMessage?text={}&chat_id={}"
BOT_ID = "7543378625:AAEOaVAQRyBItEtUFZ8198DxovyS_eEnEeU"


def send_message(message):
    message = (f'Name: {message.name}\n'
               f'email: {message.email}\n'
               f'phone: {message.phone}\n'
               '\n'
               f'message: {message.message}'
               '\n'
               f'date: {message.created_at.strftime("%d/%m/%Y %H:%M:%S")}'

               )
    response = requests.get(TELEGRAMBOT_URL.format(BOT_ID, message, CHAT_ID))
    return response
