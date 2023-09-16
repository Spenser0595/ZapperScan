import telegram
import nmap
import whois

# Fournissez le token généré par Botfather
TOKEN =  " Token"
bot = telegram.Bot(token=TOKEN)

def scan(bot, update):
    # Récupère le nom de domaine et le port entrés par l'utilisateur
    input_params = update.message.text.split()
    domain = input_params[0]
    port = input_params[1] if len(input_params) > 1 else '80'

    # Effectue un scan Nmap sur le port spécifié pour le domaine donné
    nm = nmap.PortScanner()
    nm.scan(domain, port)
    scan_result = nm[domain]['tcp'][int(port)]

    # Effectue un scan WHOIS sur le domaine donné
    w = whois.whois(domain)
    # Crée le message de réponse du bot contenant les résultats des scans
    response = "Résultats du scan Nmap pour {} sur le port {} : \".format(domain, port)
    response += "Etat du port : {}\".format(scan_result['state'])
    if scan_result['state'] == 'open':
        response += "Service : {}\".format(scan_result['name'])
    response += "\Résultats du scan WHOIS : \"
    response += "Nom de domaine : {}\".format(w.domain_name)
    response += "Propriétaire : {}\".format(w.name)
    response += "Email du propriétaire : {}".format(w.emails[0])

    # Envoi de la réponse à l'utilisateur via Telegram
    bot.send_message(chat_id=update.message.chat_id, text=response)

# Initialise le bot et lie la fonction scan à la commande /scan
updater = telegram.ext.Updater(token=TOKEN)
updater.dispatcher.add_handler(telegram.ext.CommandHandler('scan', scan))
updater.start_polling()
