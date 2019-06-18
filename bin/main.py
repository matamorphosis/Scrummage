#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, flash, request, redirect, url_for, session, send_from_directory
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from crontab import CronTab
from logging.handlers import RotatingFileHandler
import os, glob, sys, re, psycopg2, datetime, json, plugin_caller, getpass, time, plugins.common.Connectors as Connectors, plugins.common.General as General, logging

File_Path = os.path.dirname(os.path.realpath('__file__'))
app = Flask(__name__, instance_path=os.path.join(File_Path, 'static/protected'))
app.permanent_session_lifetime = timedelta(minutes=5)
Valid_Plugins = ["Ahmia Darkweb Search", "Blockchain Bitcoin Address Search", "Blockchain Bitcoin Cash Address Search", "Blockchain Ethereum Address Search", "Blockchain Bitcoin Transaction Search", "Blockchain Bitcoin Cash Transaction Search", "Blockchain Ethereum Transaction Search", "Certificate Transparency", "Craigslist Search", "Domain Fuzzer - All Extensions",
                 "Domain Fuzzer - Alpha-Linguistic Character Switcher", "Domain Fuzzer - Global Domain Suffixes", "Domain Fuzzer - Regular Domain Suffixes", "Ebay Search", "Google Search", "Have I Been Pwned - Password Search",
                 "Have I Been Pwned - Email Search", "Have I Been Pwned - Breach Search", "Have I Been Pwned - Account Search", "Instagram Location Search", "Instagram Media Search", "Instagram Tag Search", "Instagram User Search", "iTunes Store Search", "PhishTank Search", "Google Play Store Search", "Reddit Search", "RSS Feed Search", "Twitter Scraper", "Windows Store Search", "YouTube Search"]
Plugins_without_Limit = ["Certificate Transparency", "Domain Fuzzer - All Extensions", "Domain Fuzzer - Alpha-Linguistic Character Switcher", "Domain Fuzzer - Global Domain Suffixes", "Domain Fuzzer - Regular Domain Suffixes", "Have I Been Pwned - Email Search", "Have I Been Pwned - Breach Search", "Have I Been Pwned - Password Search", "Instagram Media Search"]
Phishing_Sites = [["All", "All"], [139, "ABL"], [201, "ABN"], [92, "ABSA Bank"], [68, "Accurint"], [207, "Adobe"], [209, "Aetna"], [211, "Alibaba.com"], [160, "Allegro"], [51, "Alliance Bank"], [28, "Amarillo"], [61, "Amazon.com"], [118, "American Airlines"], [184, "American Express"], [141, "American Greetings"], [15, "Ameritrade"], [133, "ANZ"], [110, "AOL"], [183, "Apple"], [170, "ArenaNet"], [144, "ASB"], [17, "Associated Bank"], [189, 'AT&T'], [165, "ATO"], [249, "B-tc.ws"], [73, "Banca di Roma"], [178, "Banca Intesa"], [124, "Bancasa"], [158, "Banco De Brasil"], [125, "Banco Real"], [208, "Bank Millennium"], [6, "Bank of America / MBNA"], [40, "Bank of KC"], [45, "Bank of the West"], [5, "Barclays"], [63, "BB&amp;T"], [27, "Bendigo"], [226, "Binance"], [217, "Bitfinex"], [224, "bitFlyer"], [229, "Bitmex"], [122, "Blizzard"], [210, "Blockchain"], [96, "BloomSpot"], [44, "BMO"], [82, "Bradesco"], [212, "BT"], [98, "BuyWithMe"], [126, "Cahoot"], [138, "Caixa"], [120, "Caixo"], [29, "Capital One"], [156, "Capitec Bank"], [65, "Career Builder"], [105, "Cariparma Credit Agricole"], [107, "Cartasi"], [131, "Centurylink"], [19, "Charter One"], [3, "Chase"], [32, "CIBC"], [137, "Cielo"], [150, "CIMB Bank"], [42, "Citibank"], [14, "Citizens"], [230, "CNB"], [146, "Co-operative Bank"], [214, "Coinbase"], [22, "Comerica"], [167, "Commonwealth Bank of Australia"], [30, "Compass"], [113, "Craigslist"], [219, "Credit Karma"], [31, "Crown"], [87, "CUA (Credit Union Australia)"], [33, "DBS"], [140, "Delta"], [185, "Deutsche Bank"], [197, "DHL"], [188, "Diners Club"], [187, "Discover Bank"], [186, "Discover Card"], [196, "Discovery"], [60, "Downey Savings"], [194, "Dropbox"], [59, "e-gold"], [2, "eBay"], [102, "Egg"], [77, "EPPICard"], [74, "Facebook"], [41, "FHB"], [48, "Fifth Third Bank"], [103, "First Direct"], [50, "First Federal Bank of California"], [91, "First National Bank (South Africa)"], [39, "Franklin"], [218, "GitHub"], [76, "Google"], [94, "Groupon"], [106, "Gruppo Carige"], [151, "GTBank"], [171, "GuildWars2"], [81, "Habbo"], [104, "Halifax"], [108, "HMRC"], [97, "HomeRun"], [154, "Hotmail"], [4, "HSBC"], [18, "Huntington"], [228, "IDEX"], [57, "Independent Bank"], [123, "ING"], [67, "Interactive Brokers"], [202, "Intesa Sanpaolo"], [62, "IRS"], [135, "Itau"], [72, "KCFCU (Kauai Credit Union)"], [20, "Key Bank"], [203, "Kiwibank"], [9, "LaSalle"], [204, "LinkedIn"], [152, "Littlewoods"], [112, "Live"], [95, "LivingSocial"], [182, "Lloyds Bank"], [215, "LocalBitcoins.com"], [179, "Lottomatica"], [12, "M &amp; I"], [130, "Mastercard"], [66, "MBTrading"], [173, "Metro Bank"], [177, "Microsoft"], [227, "MyCrypto"], [223, "MyEtherWallet"], [225, "MyMonero"], [78, "MySpace"], [164, "NAB"], [37, "Nantucket Bank"], [34, "National City"], [148, "Nationwide"], [26, "NatWest"], [71, "Nedbank"], [200, "Netflix"], [161, "Nets"], [205, "NetSuite"], [127, "NEXON"], [175, "Nordea"], [149, "Northern Rock"], [168, "Orange"], [89, "Orkut"], [8, "Other"], [159, "otoMoto"], [192, "PagSeguro"], [216, "Paxful"], [1, "PayPal"], [23, "Peoples"], [195, "Permanent TSB"], [180, "Pintrest"], [176, "PKO"], [114, "Playdom"], [115, "Playfish"], [100, "Plum District"], [69, "PNC Bank"], [64, "Poste"], [128, "Rabobank"], [221, "Rackspace"], [36, "RBC"], [70, "RBS"], [16, "Regions"], [134, "RuneScape"], [121, "Safra National Bank of New York"], [35, "Salem Five"], [75, "Salesforce"], [109, "Santander UK"], [84, "Scotiabank"], [55, "Sky Financial"], [117, "Skype"], [147, "Smile Bank"], [93, "South African Revenue Service"], [166, "St George Bank"], [90, "Standard Bank Ltd."], [86, "Steam"], [163, "Suncorp"], [172, "Swedbank"], [145, "Tagged"], [136, "TAM Fidelidade"], [43, "TD Canada Trust"], [193, "Tesco"], [85, "Tibia"], [99, "Tippr"], [181, "TSB"], [132, "Twitter"], [213, "Uber"], [220, "UniCredit"], [157, "US Airways"], [24, "US Bank"], [199, "USAA"], [169, "Verizon"], [153, "Very"], [248, "Virustotal"], [129, "Visa"], [155, "Vodafone"], [58, "Volksbanken Raiffeisenbanken"], [13, "Wachovia"], [56, "WalMart"], [21, "Washington Mutual"], [7, "Wells Fargo"], [53, "Western Union"], [25, "Westpac"], [206, "WhatsApp"], [88, "World of Warcraft"], [222, "Xapo"], [111, "Yahoo"], [116, "ZML"], [101, "Zynga"]]
Bad_Characters = ["|", "&", "?", "\\", "\"", "\'", "[", "]", ">", "<", "~", "`", ";", "{", "}", "%", "^", "--", "++", "+", "'", "(", ")", "*", "="]
Finding_Types = ['Domain Spoof', 'Data Leakage', 'Phishing', 'Blockchain Transaction', 'Blockchain Address']

Connection = Connectors.Load_Main_Database()
Cursor = Connection.cursor()

def Create_Event(Description):
    Cursor.execute("INSERT INTO events (description, created_at) VALUES (%s,%s)", (Description, datetime.datetime.now()))
    Connection.commit()

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html', username=session.get('user')), 404

app.register_error_handler(404, page_not_found)

@app.route('/')
def index():
    if session.get('user'):
        return render_template('dashboard.html', username=session.get('user'))

    else:
        return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    User_Bad_Chars = 0
    Password_Bad_Chars = 0
    User_Check = False

    if request.method == 'POST' or request.method == 'GET':

        if request.method == 'POST':
            Username = request.form['username']

            for char in Username:

                if char in Bad_Characters:
                    return render_template('login.html', error="Please enter a valid username and password.")

            Password = request.form['password']
            PSQL_Select_Query = 'SELECT * FROM users WHERE username = %s'
            Cursor.execute(PSQL_Select_Query, (Username,))
            User = Cursor.fetchone()

            if User[1] == Username:
                User_Check = True

            Password_Check = check_password_hash(User[2], Password)

            if User_Check != True or Password_Check != True:

                for char in Username:

                    if char in Bad_Characters:
                        User_Bad_Chars = 1

                for char in Password:

                    if char in Bad_Characters:
                        Password_Bad_Chars = 1

                if User_Bad_Chars == 1 and Password_Bad_Chars == 1:
                    Message = "Failed login attempt for a provided username and password, both with potentially dangerous characters."
                    app.logger.warning(Message)
                    Create_Event(Message)

                elif User_Bad_Chars == 0 and Password_Bad_Chars == 1:
                    Message = "Failed login attempt for the provided username: " + Username + " with a password that contains potentially dangerous characters."
                    app.logger.warning(Message)
                    Create_Event(Message)

                elif User_Bad_Chars == 1 and Password_Bad_Chars == 0:
                    Message = "Failed login attempt for a provided username that contained potentially dangerous characters."
                    app.logger.warning(Message)
                    Create_Event(Message)

                else:
                    Message = "Failed login attempt for the user: " + Username + "."
                    app.logger.warning(Message)
                    Create_Event(Message)

                return render_template('login.html', error='Login Unsuccessful')

            else:
                session['user'] = Username
                session['is_admin'] = User[4]
                session['form_step'] = 0
                session['form_type'] = ""
                session['task_frequency'] = ""
                session['task_description'] = ""
                session['task_limit'] = 0
                session['task_query'] = ""
                session['task_id'] = ""
                Message = "Successful login from " + Username + "."
                app.logger.warning(Message)
                Create_Event(Message)

                return redirect(url_for('dashboard'))

        else:
            return render_template('login.html')

        return render_template('login.html')

    else:
        return redirect(url_for('no_method'))

@app.route('/nosession')
def no_session():
    return render_template('no_session.html')

def requirement(f):
    @wraps(f)
    def wrap(*args, **kwargs):

        if session.get('user'):
            return f(*args, **kwargs)

        else:
            flash('You need to login first.')
            return redirect(url_for('no_session'))

    return wrap

@app.route('/static/protected/<path:filename>')
@requirement
def protected(filename):
    try:
        return send_from_directory(os.path.join(app.instance_path, ''), filename)

    except Exception as e:
        app.logger.error(e)

@app.after_request
def apply_caching(response):

    try:
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["X-Content-Type"] = "nosniff"
        # response.headers["Content-Security-Policy"] = "script-src 'self'"
        response.headers["Server"] = ""
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, pre-check=0, post-check=0, max-age=0, s-maxage=0"
        return response

    except Exception as e:
        app.logger.error(e)

@app.route('/about')
def about():
    return render_template('about.html', username=session.get('user'))

@app.route('/screenshot', methods=['POST'])
def screenshot():

    if session.get('user'):

        if request.method == 'POST':
            ss_id = 0

            if 'ss_id' in request.form:

                try:
                    ss_id = int(request.form['ss_id'])
                    PSQL_Select_Query = 'SELECT link FROM results WHERE result_id = %s'
                    Cursor.execute(PSQL_Select_Query, (ss_id,))
                    result = Cursor.fetchone()

                    if '.onion' in result[0]:
                        return redirect(url_for('results'))

                    else:
                        screenshot_file = result[0].replace("http://", "")
                        screenshot_file = screenshot_file.replace("https://", "")

                        if screenshot_file.endswith('/'):
                            screenshot_file = screenshot_file[:-1]

                        screenshot_file = screenshot_file.replace("/", "-")
                        screenshot_file = screenshot_file.replace("?", "-")
                        screenshot_file = screenshot_file.replace("=", "-") + ".png"

                        CHROME_PATH = '/usr/bin/google-chrome'
                        CHROMEDRIVER_PATH = '/usr/bin/chromedriver'
                        # WINDOW_SIZE = "1920,1080"

                        chrome_options = Options()
                        chrome_options.add_argument("--headless")
                        # chrome_options.add_argument("--window-size=%s" % WINDOW_SIZE)
                        chrome_options.binary_location = CHROME_PATH

                        driver = webdriver.Chrome(
                            executable_path=CHROMEDRIVER_PATH,
                            chrome_options=chrome_options
                        )

                        driver.get(result[0])
                        # total_width = driver.execute_script("return document.body.offsetWidth")
                        total_height = driver.execute_script("return document.body.scrollHeight")
                        driver.set_window_size(1920, total_height)
                        driver.save_screenshot("static/protected/screenshots/" + screenshot_file)
                        driver.close()

                        PSQL_Update_Query = 'UPDATE results SET screenshot_url = %s WHERE result_id = %s'
                        Cursor.execute(PSQL_Update_Query, (screenshot_file, ss_id,))
                        Connection.commit()

                except:
                    return redirect(url_for('results'))

            return redirect(url_for('results'))

        else:
            return redirect(url_for('no_method'))

    else:
        return redirect(url_for('no_session'))

@app.route('/nomethod')
def no_method():
    return render_template('nomethod.html', username=session.get('user'))

@app.route('/dashboard')
def dashboard():

    if session.get('user'):

        try:
            labels = Finding_Types
            colors = ["#2471A3", "#8B008B", "#DC143C", "#FFA500", "#DAFF00"]

            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
            Cursor.execute(PSQL_Select_Query, ("Open", "Domain Spoof",))
            open_domain_spoof_results = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
            Cursor.execute(PSQL_Select_Query, ("Open", "Data Leakage",))
            open_data_leakages = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
            Cursor.execute(PSQL_Select_Query, ("Open", "Phishing",))
            open_phishing_results = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
            Cursor.execute(PSQL_Select_Query, ("Open", "Blockchain Transaction",))
            open_blockchain_transaction_results = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
            Cursor.execute(PSQL_Select_Query, ("Open", "Blockchain Address",))
            open_blockchain_address_results = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
            Cursor.execute(PSQL_Select_Query, ("Closed", "Domain Spoof",))
            closed_domain_spoof_results = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
            Cursor.execute(PSQL_Select_Query, ("Closed", "Data Leakage",))
            closed_data_leakages = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
            Cursor.execute(PSQL_Select_Query, ("Closed", "Phishing",))
            closed_phishing_results = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
            Cursor.execute(PSQL_Select_Query, ("Closed", "Blockchain Transaction",))
            closed_blockchain_transaction_results = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
            Cursor.execute(PSQL_Select_Query, ("Closed", "Blockchain Address",))
            closed_blockchain_address_results = Cursor.fetchall()

            Mixed_Options = ['Inspecting', 'Reviewing']

            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE result_type = %s AND status = ANY (%s);'
            Cursor.execute(PSQL_Select_Query, ("Domain Spoof", Mixed_Options,))
            mixed_domain_spoof_results = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE result_type = %s AND status = ANY (%s);'
            Cursor.execute(PSQL_Select_Query, ("Data Leakage", Mixed_Options,))
            mixed_data_leakages = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE result_type = %s AND status = ANY (%s);'
            Cursor.execute(PSQL_Select_Query, ("Phishing", Mixed_Options,))
            mixed_phishing_results = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE result_type = %s AND status = ANY (%s);'
            Cursor.execute(PSQL_Select_Query, ("Blockchain Transaction", Mixed_Options,))
            mixed_blockchain_transaction_results = Cursor.fetchall()
            PSQL_Select_Query = 'SELECT count(*) FROM results WHERE result_type = %s AND status = ANY (%s);'
            Cursor.execute(PSQL_Select_Query, ("Blockchain Address", Mixed_Options,))
            mixed_blockchain_address_results = Cursor.fetchall()

            open_values = [open_domain_spoof_results[0][0], open_data_leakages[0][0], open_phishing_results[0][0], open_blockchain_transaction_results[0][0], open_blockchain_address_results[0][0]]
            closed_values = [closed_domain_spoof_results[0][0], closed_data_leakages[0][0], closed_phishing_results[0][0], closed_blockchain_transaction_results[0][0], closed_blockchain_address_results[0][0]]
            mixed_values = [mixed_domain_spoof_results[0][0], mixed_data_leakages[0][0], mixed_phishing_results[0][0], mixed_blockchain_transaction_results[0][0], mixed_blockchain_address_results[0][0]]

            return render_template('dashboard.html', username=session.get('user'), max=17000, open_set=zip(open_values, labels, colors), closed_set=zip(closed_values, labels, colors), mixed_set=zip(mixed_values, labels, colors))

        except Exception as e:
            app.logger.error(e)

    else:
        return redirect(url_for('no_session'))

@app.route('/dropsession')
def dropsession():

    try:
        username = session.get('user')
        session.pop('user', None)
        session.pop('is_admin', False)
        Message = "Session for user: " + username + " terminated."
        app.logger.warning(Message)
        Create_Event(Message)
        return render_template('index.html', loggedout=True)

    except Exception as e:
        app.logger.error(e)
        return render_template('index.html', loggedout=True)

@app.route('/events', methods=['GET'])
def events():

    if session.get('user'):

        if request.method == 'GET':

            PSQL_Select_Query = "SELECT * FROM events ORDER BY event_id DESC LIMIT 1000"
            Cursor.execute(PSQL_Select_Query)
            events = Cursor.fetchall()
            return render_template('events.html', username=session.get('user'), events=events)

        else:
            return redirect(url_for('no_method'))

    else:
        return redirect(url_for('no_session'))

@app.route('/tasks', methods=['GET', 'POST'])
def tasks():
    results = []

    if session.get('user'):

        if request.method == 'POST' or request.method == 'GET':

            if request.method == 'POST':

                if session.get('is_admin'):

                    if 'dup0' in request.form:

                        try:
                            dup_id = int(request.form['dup0'])
                            Cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (dup_id,))
                            result = Cursor.fetchone()

                            if result:
                                Current_Timestamp = datetime.datetime.now()  # Variable set to create consistency in timestamps across two seperate database queries.
                                PSQL_Insert_Query = 'INSERT INTO tasks (query, plugin, description, frequency, task_limit, status, created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)'
                                Cursor.execute(PSQL_Insert_Query, (result[1], result[2], result[3], result[4], str(result[5]), "Stopped", str(Current_Timestamp), str(Current_Timestamp)))
                                Connection.commit()

                                if result[4]:
                                    time.sleep(1)
                                    PSQL_Select_Query = "SELECT * FROM tasks WHERE query = %s AND plugin = %s AND description = %s AND frequency = %s AND task_limit = %s AND status = %s AND created_at = %s AND updated_at = %s;"
                                    Cursor.execute(PSQL_Select_Query, (
                                    result[1], result[2], result[3], result[4], str(result[5]), "Stopped",
                                    str(Current_Timestamp), str(Current_Timestamp),))
                                    result = Cursor.fetchone()
                                    task_id = result[0]

                                    try:
                                        my_cron = CronTab(user=getpass.getuser())
                                        job = my_cron.new(command='/usr/bin/python3 ' + File_Path + '/plugin_caller.py -t ' + str(task_id))
                                        job.setall(result[4])
                                        my_cron.write()

                                    except Exception as e:
                                        app.logger.error(e)

                                Message = "Task ID " + str(dup_id) + " duplicated by " + session.get('user') + "."
                                app.logger.warning(Message)
                                Create_Event(Message)

                        except Exception as e:
                            app.logger.error(e)

                    elif 'return' in request.form:

                        if session.get('form_step') == 1:

                            try:
                                session['form_step'] = 0

                            except Exception as e:
                                app.logger.error(e)

                        elif session.get('form_step') == 2:

                            try:
                                session['form_step'] -= 1
                                return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'), is_admin=session.get('is_admin'), form_step=session.get('form_step'), new_task=True, frequency_field=session.get('task_frequency'), description_field=session.get('task_description'), task_type_field=session.get('form_type'), Valid_Plugins=Valid_Plugins)

                            except Exception as e:
                                app.logger.error(e)

                    elif 'edittask' in request.form:

                        if session.get('form_step') == 0:

                            try:
                                session['task_id'] = int(request.form['edittask'])
                                PSQL_Select_Query = "SELECT * FROM tasks WHERE task_id = %s;"
                                Cursor.execute(PSQL_Select_Query, (session.get('task_id'),))
                                results = Cursor.fetchone()

                                if results:
                                    session['form_step'] += 1
                                    return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                           edit_task=True, Valid_Plugins=Valid_Plugins,
                                                           is_admin=session.get('is_admin'), results=results)

                                else:
                                    PSQL_Select_Query = "SELECT * FROM tasks;"
                                    Cursor.execute(PSQL_Select_Query, (session.get('task_id'),))
                                    results = Cursor.fetchall()
                                    return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                           Valid_Plugins=Valid_Plugins, results=results,
                                                           is_admin=session.get('is_admin'),
                                                           error="Invalid value provided. Failed to edit object.")

                            except:
                                PSQL_Select_Query = "SELECT * FROM tasks;"
                                Cursor.execute(PSQL_Select_Query, (session.get('task_id'),))
                                results = Cursor.fetchall()
                                return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                       Valid_Plugins=Valid_Plugins, results=results,
                                                       is_admin=session.get('is_admin'),
                                                       error="Invalid value provided. Failed to edit object.")

                        elif session.get('form_step') == 1:
                            PSQL_Select_Query = "SELECT * FROM tasks WHERE task_id = %s;"
                            Cursor.execute(PSQL_Select_Query, (session.get('task_id'),))
                            results = Cursor.fetchone()

                            if 'tasktype' in request.form:

                                if request.form['tasktype'] in Valid_Plugins:

                                    if request.form['frequency']:
                                        session['task_frequency'] = request.form['frequency']
                                        task_frequency_regex = re.search(
                                            r"[\d\/\*\-\,]+\s[\d\/\*\-\,]+\s[\d\/\*\-\,]+\s[\d\/\*\-\,]+\s[\d\/\*\-\,]+", session.get('task_frequency'))

                                        if not task_frequency_regex and not session.get('task_frequency') == "":
                                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                                   edit_task=True, Valid_Plugins=Valid_Plugins,
                                                                   results=results, is_admin=session.get('is_admin'),
                                                                   error="Invalid frequency, please provide a valid frequency in the same way you would set up a cronjob or leave the field blank. i.e. \"* /5 * * *\"")

                                    if 'description' in request.form:
                                        session['task_description'] = request.form['description']

                                    session['form_type'] = request.form['tasktype']
                                    session['form_step'] += 1

                                    if session.get('form_type') not in Plugins_without_Limit:
                                        return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                               use_limit=True, edit_task=True,
                                                               Valid_Plugins=Valid_Plugins,
                                                               is_admin=session.get('is_admin'), results=results)

                                    else:

                                        if request.form['tasktype'] == "PhishTank Search":
                                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), edit_task=True, Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'), results=results, phish_sites=Phishing_Sites)

                                        else:
                                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), edit_task=True, Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'), results=results)

                                else:
                                    return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                           edit_task=True, Valid_Plugins=Valid_Plugins,
                                                           is_admin=session.get('is_admin'), results=results,
                                                           error="Invalid task type, please select an option from the provided list for the Task Type field.")

                            else:
                                return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                       edit_task=True, Valid_Plugins=Valid_Plugins,
                                                       is_admin=session.get('is_admin'), results=results,
                                                       error="Missing field, please enter a name and select an option from the provided list for the Task Type field.")

                        elif session.get('form_step') == 2:
                            PSQL_Select_Query = "SELECT * FROM tasks WHERE task_id = %s;"
                            Cursor.execute(PSQL_Select_Query, (session.get('task_id'),))
                            results = Cursor.fetchone()

                            if 'query' in request.form:

                                if request.form['query']:
                                    Frequency_Error = ""
                                    session['task_query'] = request.form['query']

                                    if 'limit' in request.form:

                                        for char in session.get('task_query'):

                                            if char in Bad_Characters:
                                                return render_template('tasks.html', username=session.get('user'),
                                                                       form_step=session.get('form_step'), use_limit=True,
                                                                       edit_task=True, Valid_Plugins=Valid_Plugins,
                                                                       results=results,
                                                                       error="Invalid query specified, please provide a valid query with no special characters.")

                                        try:
                                            session['task_limit'] = int(request.form['limit'])

                                        except:
                                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                                   use_limit=True, edit_task=True,
                                                                   Valid_Plugins=Valid_Plugins, results=results,
                                                                   error="Invalid limit specified, please provide a valid limit represented by a number.")

                                    else:

                                        for char in session.get('task_query'):

                                            if char in Bad_Characters:
                                                return render_template('tasks.html', username=session.get('user'),
                                                                       form_step=session.get('form_step'), edit_task=True,
                                                                       Valid_Plugins=Valid_Plugins, results=results,
                                                                       error="Invalid query specified, please provide a valid query with no special characters.")


                                        if session.get("form_type") == "PhishTank Search":

                                            if not any(session['task_query'] in p for p in Phishing_Sites):
                                                return render_template('tasks.html', username=session.get('user'),
                                                                       form_type=session.get('form_type'), form_step=session.get('form_step'),
                                                                       is_admin=session.get('is_admin'), phish_sites=Phishing_Sites, edit_task=True,
                                                                       error="Invalid query selected, please choose a pre-defined query from the list.")

                                    Update_Cron = False
                                    original_frequency = ""

                                    if session.get('task_frequency') != "":
                                        PSQL_Select_Query = "SELECT frequency FROM tasks WHERE task_id = %s;"
                                        Cursor.execute(PSQL_Select_Query, (session.get('task_id'),))
                                        result = Cursor.fetchone()
                                        original_frequency = result[0]

                                        if not original_frequency == session.get('task_frequency'):
                                            Update_Cron = True

                                    else:

                                        if results[4] != "":

                                            try:
                                                my_cron = CronTab(user=getpass.getuser())

                                                for job in my_cron:

                                                    if job.command == '/usr/bin/python3 ' + File_Path + '/plugin_caller.py -t ' + str(session.get('task_id')):
                                                        my_cron.remove(job)
                                                        my_cron.write()

                                            except:
                                                return render_template('tasks.html', username=session.get('user'),
                                                                       form_type=session.get('form_type'), form_step=session.get('form_step'),
                                                                       is_admin=session.get('is_admin'), phish_sites=Phishing_Sites, edit_task=True,
                                                                       error="Failed to update cron job.")

                                    PSQL_Update_Query = 'UPDATE tasks SET query = %s, plugin = %s, description = %s, frequency = %s, task_limit = %s, updated_at = %s WHERE task_id = %s'
                                    Cursor.execute(PSQL_Update_Query, (session.get('task_query'), session.get('form_type'), session.get('task_description'), session.get('task_frequency'), session.get('task_limit'),
                                    datetime.datetime.now(), session.get('task_id'),))
                                    Connection.commit()
                                    time.sleep(1)

                                    if Update_Cron:
                                        PSQL_Select_Query = "SELECT * FROM tasks WHERE task_id = %s;"
                                        Cursor.execute(PSQL_Select_Query, (session.get('task_id'),))
                                        result = Cursor.fetchone()
                                        current_task_id = result[0]

                                        try:
                                            my_cron = CronTab(user=getpass.getuser())

                                            for job in my_cron:

                                                if job.command == '/usr/bin/python3 ' + File_Path + '/plugin_caller.py -t ' + str(current_task_id):
                                                    my_cron.remove(job)
                                                    my_cron.write()

                                            job = my_cron.new(command='/usr/bin/python3 ' + File_Path + '/plugin_caller.py -t ' + str(current_task_id))
                                            job.setall(session.get('task_frequency'))
                                            my_cron.write()

                                        except:
                                            Frequency_Error = "Task updated but no cronjob was added, and any valid original cron jobs for this task have been removed due to an invalid frequency being supplied, please double check the frequency for task ID " + str(task_id) + " and use the \"Edit\" button to edit the frequency to create a cronjob."

                                    session['form_step'] = 0
                                    Message = "Task ID " + str(session.get('task_id')) + " updated by " + session.get('user') + "."
                                    app.logger.warning(Message)
                                    Create_Event(Message)
                                    session['task_id'] = ""
                                    PSQL_Select_Query = "SELECT * FROM tasks"
                                    Cursor.execute(PSQL_Select_Query)
                                    results = Cursor.fetchall()
                                    return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                           results=results, is_admin=session.get('is_admin'),
                                                           error=Frequency_Error)

                                else:
                                    return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                           results=results, is_admin=session.get('is_admin'),
                                                           error="The Query field cannot be left blank.")

                            else:
                                return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                       results=results, is_admin=session.get('is_admin'),
                                                       error="Empty query, please provide a valid term to search for.")

                        else:
                            session['form_type'] = 0
                            PSQL_Select_Query = "SELECT * FROM tasks"
                            Cursor.execute(PSQL_Select_Query)
                            results = Cursor.fetchall()
                            return redirect('tasks.html', username=session.get('user'), is_admin=session.get('is_admin'), results=results)

                    elif 'delete_id' in request.form:

                        try:
                            del_id = int(request.form['delete_id'])
                            PSQL_Select_Query = "SELECT frequency FROM tasks WHERE task_id = %s"
                            Cursor.execute(PSQL_Select_Query, (del_id,))
                            result = Cursor.fetchone()

                            if result:

                                try:
                                    my_cron = CronTab(user=getpass.getuser())

                                    for job in my_cron:

                                        if job.command == '/usr/bin/python3 ' + File_Path + '/plugin_caller.py -t ' + str(del_id):
                                            my_cron.remove(job)
                                            my_cron.write()

                                except:
                                    PSQL_Select_Query = "SELECT * FROM tasks"
                                    Cursor.execute(PSQL_Select_Query)
                                    results = Cursor.fetchall()
                                    return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                           is_admin=session.get('is_admin'), results=results,
                                                           error="Failed to remove task ID " + str(
                                                               del_id) + " from crontab.")

                            del_id = int(request.form['delete_id'])
                            PSQL_Delete_Query = "DELETE FROM tasks WHERE task_id = %s;"
                            Cursor.execute(PSQL_Delete_Query, (del_id,))
                            Connection.commit()
                            Message = "Task ID " + str(del_id) + " deleted by " + session.get('user') + "."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            PSQL_Select_Query = "SELECT * FROM tasks"
                            Cursor.execute(PSQL_Select_Query)
                            results = Cursor.fetchall()

                            if results:
                                return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'), results=results)

                            else:
                                return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'), results=results,
                                                       error="Invalid value provided. Failed to delete object.")

                        except:
                            PSQL_Select_Query = "SELECT * FROM tasks"
                            Cursor.execute(PSQL_Select_Query)
                            results = Cursor.fetchall()
                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                   is_admin=session.get('is_admin'), results=results,
                                                   error="Invalid value provided. Failed to delete object.")

                    elif 'newtask' in request.form:

                        if session.get('form_step') == 0:
                            session['form_step'] += 1
                            return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'),
                                                   is_admin=session.get('is_admin'), form_step=session.get('form_step'), new_task=True,
                                                   Valid_Plugins=Valid_Plugins)

                        elif session.get('form_step') == 1:

                            if 'tasktype' in request.form:

                                if request.form['tasktype'] in Valid_Plugins:

                                    if 'frequency' in request.form:
                                        session['task_frequency'] = request.form['frequency']
                                        task_frequency_regex = re.search(
                                            r"[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}", session.get('task_frequency'))

                                        if not task_frequency_regex and not session.get('task_frequency') == "":
                                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                                   form_type=session.get('form_type'),
                                                                   is_admin=session.get('is_admin'), new_task=True,
                                                                   error="Invalid frequency, please provide a valid frequency in the same way you would set up a cronjob or leave the field blank. i.e. \"* */5 * * *\"")

                                    if 'description' in request.form:
                                        session['task_description'] = request.form['description']

                                    session['form_type'] = request.form['tasktype']
                                    session['form_step'] += 1

                                    if session.get('form_type') not in Plugins_without_Limit:
                                        return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'),
                                                               new_task=True, is_admin=session.get('is_admin'),
                                                               form_step=session.get('form_step'), use_limit=True)

                                    else:

                                        if session.get('form_type') == "PhishTank Search":
                                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), new_task=True, Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'), results=results, phish_sites=Phishing_Sites)

                                        else:
                                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), new_task=True, Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'), results=results)


                                else:
                                    return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'),
                                                           new_task=True, Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'),
                                                           form_step=session.get('form_step'),
                                                           error="Invalid task type, please select an option from the provided list for the Task Type field.")

                            else:
                                return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'),
                                                       new_task=True, Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'),
                                                       form_step=session.get('form_step'),
                                                       error="Missing field, please enter a name and select an option from the provided list for the Task Type field.")

                        elif session.get('form_step') == 2:

                            if 'query' in request.form:

                                if request.form['query']:
                                    Frequency_Error = ""
                                    session['task_query'] = request.form['query']

                                    if 'limit' in request.form:

                                        for char in session.get('task_query'):

                                            if char in Bad_Characters:
                                                return render_template('tasks.html', username=session.get('user'),
                                                                       form_type=session.get('form_type'), form_step=session.get('form_step'),
                                                                       is_admin=session.get('is_admin'), new_task=True,
                                                                       use_limit=True,
                                                                       error="Invalid query specified, please provide a valid query with no special characters.")

                                        try:
                                            session['task_limit'] = int(request.form['limit'])

                                        except:
                                            return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'),
                                                                   form_step=session.get('form_step'),
                                                                   is_admin=session.get('is_admin'), new_task=True,
                                                                   use_limit=True,
                                                                   error="Invalid limit specified, please provide a valid limit represented by a number.")

                                    else:

                                        for char in session.get('task_query'):

                                            if char in Bad_Characters:
                                                return render_template('tasks.html', username=session.get('user'),
                                                                       form_type=session.get('form_type'), form_step=session.get('form_step'),
                                                                       is_admin=session.get('is_admin'), new_task=True,
                                                                       error="Invalid query specified, please provide a valid query with no special characters.")

                                        if session.get("form_type") == "PhishTank Search":

                                            if not any(session['task_query'] in p for p in Phishing_Sites):
                                                return render_template('tasks.html', username=session.get('user'),
                                                                       form_type=session.get('form_type'), form_step=session.get('form_step'),
                                                                       is_admin=session.get('is_admin'), phish_sites=Phishing_Sites, new_task=True,
                                                                       error="Invalid query selected, please choose a pre-defined query from the list.")


                                    Current_Timestamp = datetime.datetime.now()  # Variable set as it is needed for two different functions and needs to be consistent.
                                    PSQL_Insert_Query = 'INSERT INTO tasks (query, plugin, description, frequency, task_limit, status, created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)'
                                    Cursor.execute(PSQL_Insert_Query, (session.get('task_query'), session.get('form_type'), session.get('task_description'), session.get('task_frequency'), session.get('task_limit'), "Stopped",
                                    Current_Timestamp, Current_Timestamp,))
                                    Connection.commit()
                                    time.sleep(1)

                                    if session.get('task_frequency'):
                                        PSQL_Select_Query = "SELECT * FROM tasks WHERE query = %s AND plugin = %s AND description = %s AND frequency = %s AND task_limit = %s AND status = %s AND created_at = %s AND updated_at = %s;"
                                        Cursor.execute(PSQL_Select_Query, (session.get('task_query'), session.get('form_type'), session.get('task_description'), session.get('task_frequency'), str(session.get('task_limit')),
                                        "Stopped", str(Current_Timestamp), str(Current_Timestamp),))
                                        result = Cursor.fetchone()
                                        current_task_id = result[0]

                                        try:
                                            my_cron = CronTab(user=getpass.getuser())
                                            job = my_cron.new(
                                                command='/usr/bin/python3 ' + File_Path + '/plugin_caller.py -t ' + str(current_task_id))
                                            job.setall(session.get('task_frequency'))
                                            my_cron.write()
                                            Message = "Task ID " + str(current_task_id) + " created by " + session.get('user') + "."
                                            app.logger.warning(Message)
                                            Create_Event(Message)

                                        except:
                                            Frequency_Error = "Task created but no cronjob was created due to the supplied frequency being invalid, please double check the frequency for task ID " + str(session.get('task_id')) + " and use the \"Edit\" button to update it in order for the cronjob to be created."

                                    session['form_step'] = 0
                                    PSQL_Select_Query = "SELECT * FROM tasks"
                                    Cursor.execute(PSQL_Select_Query)
                                    results = Cursor.fetchall()

                                    if Frequency_Error:
                                        return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                               new_task=True, is_admin=session.get('is_admin'),
                                                               results=results, error=Frequency_Error)

                                else:
                                    return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'),
                                                           form_step=session.get('form_step'), new_task=True,
                                                           is_admin=session.get('is_admin'),
                                                           error="The Query field cannot be left blank.")

                            else:
                                return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'),
                                                       form_step=session.get('form_step'), new_task=True,
                                                       is_admin=session.get('is_admin'),
                                                       error="Empty query, please provide a valid term to search for.")

                        else:
                            session['form_type'] = 0
                            PSQL_Select_Query = "SELECT * FROM tasks"
                            Cursor.execute(PSQL_Select_Query)
                            results = Cursor.fetchall()
                            return redirect('tasks.html', username=session.get('user'), results=results,
                                            is_admin=session.get('is_admin'))

                    elif 'runtask' in request.form:

                        try:
                            Plugin_ID = int(request.form['runtask'])
                            PSQL_Select_Query = "SELECT * FROM tasks WHERE task_id = %s;"
                            Cursor.execute(PSQL_Select_Query, (Plugin_ID,))
                            result = Cursor.fetchone()

                            if result[6] == "Running":
                                PSQL_Select_Query = "SELECT * FROM tasks"
                                Cursor.execute(PSQL_Select_Query)
                                task_results = Cursor.fetchall()
                                return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'), results=task_results,
                                                       error="Task is already running.")

                            else:
                                plugin_caller.Call_Plugin(Plugin_Name=result[2], Limit=result[5], Query=result[1], Task_ID=Plugin_ID)

                        except Exception as e:
                            app.logger.error(e)

                    else:
                        pass

                else:
                    pass

            elif request.method == 'GET':
                session['form_step'] = 0
                session['form_type'] = ""
                session['task_frequency'] = ""
                session['task_description'] = ""
                session['task_limit'] = 0
                session['task_query'] = ""
                session['task_id'] = ""

            PSQL_Select_Query = "SELECT * FROM tasks"
            Cursor.execute(PSQL_Select_Query)
            task_results = Cursor.fetchall()
            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), results=task_results)

        else:
            return redirect(url_for('no_method'))

    else:
        return redirect(url_for('no_session'))

@app.route('/results', methods=['GET', 'POST'])
def results():

    if session.get('user'):

        if request.method == 'POST' or request.method == 'GET':

            if request.method == 'POST':

                if session.get('is_admin'):

                    if 'newresult' in request.form:

                        if session.get('form_step') == 0:
                            session['form_step'] += 1
                            return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                                   is_admin=session.get('is_admin'))

                        elif session.get('form_step') == 1:
                            name = request.form['name']
                            URL = request.form['url']
                            Type = request.form['type']

                            if name and URL and Type:

                                for char in Bad_Characters:

                                    if char in name:
                                        return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                                               is_admin=session.get('is_admin'),
                                                               error="Bad characters identified in the name field, please remove special characters from the name field.")

                                if not Type in Finding_Types:
                                    return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                                           is_admin=session.get('is_admin'),
                                                           error="Result type is not valid.")

                                Query_List = General.Convert_to_List(name)
                                Hosts_List = General.Convert_to_List(URL)
                                Iterator_List = []
                                i = 0

                                while i < len(Hosts_List) and len(Query_List):
                                    URL_Regex = re.search(
                                        r"https?:\/\/(www\.)?([a-z\.]+\.\w{2,3}(\.\w{2,3})?(\.\w{2,3})?)",
                                        Hosts_List[i])

                                    if URL_Regex:
                                        Iterator_List.append(i)
                                        i += 1

                                    else:
                                        return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                                               is_admin=session.get('is_admin'),
                                                               error="Invalid URL(s).")

                                for Iterator in Iterator_List:
                                    URL_Regex = re.search(
                                        r"https?:\/\/(www\.)?([a-z\.]+\.\w{2,3}(\.\w{2,3})?(\.\w{2,3})?)",
                                        Hosts_List[Iterator])

                                    try:
                                        PSQL_Insert_Query = 'INSERT INTO results (title, status, domain, link, created_at, result_type) VALUES (%s,%s,%s,%s,%s,%s)'
                                        Cursor.execute(PSQL_Insert_Query, (
                                        Query_List[Iterator], "Open", URL_Regex.group(2), Hosts_List[Iterator],
                                        datetime.datetime.now(), Type,))
                                        Connection.commit()

                                    except Exception as e:
                                        app.logger.error(e)

                                session['form_step'] = 0
                                PSQL_Select_Query = "SELECT * FROM results ORDER BY result_id DESC LIMIT 1000"
                                Cursor.execute(PSQL_Select_Query)
                                return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'), results=Cursor.fetchall())

                            else:
                                return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'),
                                                       error="Invalid entry / entries, please fill out all necessary fields.")

                    elif 'return' in request.form:

                        try:
                            session['form_step'] = 0

                        except Exception as e:
                            app.logger.error(e)

                    elif 'delete' in request.form:

                        try:
                            result_id = int(request.form['delete'])
                            PSQL_Select_Query = "SELECT * FROM results WHERE result_id = %s"
                            Cursor.execute(PSQL_Select_Query, (result_id,))
                            Result = Cursor.fetchone()

                            if Result[6]:
                                Screenshot_File = File_Path + "/static/protected/screenshots/" + Result[9]

                                if os.path.exists(Screenshot_File):
                                    os.remove(Screenshot_File)

                            if Result[7]:
                                Output_File = File_Path + "/" + Result[10]

                                if os.path.exists(Output_File):
                                    os.remove(Output_File)

                            PSQL_Delete_Query = "DELETE FROM results WHERE result_id = %s;"
                            Cursor.execute(PSQL_Delete_Query, (result_id,))
                            Connection.commit()
                            Message = "Result ID " + str(result_id) + " deleted by " + session.get('user') + "."
                            app.logger.warning(Message)
                            Create_Event(Message)

                        except:
                            PSQL_Select_Query = "SELECT * FROM results ORDER BY result_id DESC LIMIT 1000"
                            Cursor.execute(PSQL_Select_Query)
                            return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                                   results=Cursor.fetchall(), is_admin=session.get('is_admin'),
                                                   error="Invalid request")

                    elif 'close' in request.form:

                        try:
                            result_id = int(request.form['close'])
                            PSQL_Update_Query = 'UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s'
                            Cursor.execute(PSQL_Update_Query, ("Closed", str(datetime.datetime.now()), result_id,))
                            Connection.commit()
                            Message = "Result ID " + str(result_id) + " closed by " + session.get('user') + "."
                            app.logger.warning(Message)
                            Create_Event(Message)

                        except:
                            PSQL_Select_Query = "SELECT * FROM results ORDER BY result_id DESC LIMIT 1000"
                            Cursor.execute(PSQL_Select_Query)
                            return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                                   results=Cursor.fetchall(), is_admin=session.get('is_admin'),
                                                   error="Invalid request")

                    elif 'open' in request.form:

                        try:
                            result_id = int(request.form['open'])
                            PSQL_Update_Query = 'UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s'
                            Cursor.execute(PSQL_Update_Query, ("Open", str(datetime.datetime.now()), result_id,))
                            Connection.commit()
                            Message = "Result ID " + str(result_id) + " re-opened by " + session.get('user') + "."
                            app.logger.warning(Message)
                            Create_Event(Message)

                        except:
                            PSQL_Select_Query = "SELECT * FROM results ORDER BY result_id DESC LIMIT 1000"
                            Cursor.execute(PSQL_Select_Query)
                            return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                                   results=Cursor.fetchall(), is_admin=session.get('is_admin'),
                                                   error="Invalid request")

                    elif 'inspect' in request.form:

                        try:
                            result_id = int(request.form['inspect'])
                            PSQL_Update_Query = 'UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s'
                            Cursor.execute(PSQL_Update_Query, ("Inspecting", str(datetime.datetime.now()), result_id,))
                            Connection.commit()
                            Message = "Result ID " + str(result_id) + " now under inspection by " + session.get('user') + "."
                            app.logger.warning(Message)
                            Create_Event(Message)

                        except:
                            PSQL_Select_Query = "SELECT * FROM results ORDER BY result_id DESC LIMIT 1000"
                            Cursor.execute(PSQL_Select_Query)
                            return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                                   results=Cursor.fetchall(), is_admin=session.get('is_admin'),
                                                   error="Invalid request")

                    elif 'review' in request.form:

                        try:
                            result_id = int(request.form['review'])
                            PSQL_Update_Query = 'UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s'
                            Cursor.execute(PSQL_Update_Query, ("Reviewing", str(datetime.datetime.now()), result_id,))
                            Connection.commit()
                            Message = "Result ID " + str(result_id) + " now under review by " + session.get('user') + "."
                            app.logger.warning(Message)
                            Create_Event(Message)

                        except:
                            PSQL_Select_Query = "SELECT * FROM results ORDER BY result_id DESC LIMIT 1000"
                            Cursor.execute(PSQL_Select_Query)
                            return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                                   results=Cursor.fetchall(), is_admin=session.get('is_admin'),
                                                   error="Invalid request")

                    else:
                        pass

                else:
                    pass

                if 'details' in request.form:

                    try:
                        Result_ID = int(request.form['details'])
                        PSQL_Select_Query = "SELECT * FROM results WHERE result_id = %s"
                        Cursor.execute(PSQL_Select_Query, (Result_ID,))
                        Result_Table_Results=Cursor.fetchone()
                        PSQL_Select_Query = "SELECT * FROM tasks WHERE task_id = %s"
                        Cursor.execute(PSQL_Select_Query, (Result_Table_Results[1],))
                        Task_Table_Results=Cursor.fetchone()
                        return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'), details=True, is_admin=session.get('is_admin'), results=Result_Table_Results, task_results=Task_Table_Results)

                    except:
                        PSQL_Select_Query = "SELECT * FROM results ORDER BY result_id DESC LIMIT 1000"
                        Cursor.execute(PSQL_Select_Query)
                        return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                               results=Cursor.fetchall(), is_admin=session.get('is_admin'),
                                               error="Invalid request")

                PSQL_Select_Query = "SELECT * FROM results ORDER BY result_id DESC LIMIT 1000"
                Cursor.execute(PSQL_Select_Query)
                return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'),
                                       is_admin=session.get('is_admin'), results=Cursor.fetchall())

            else:
                session['form_step'] = 0
                PSQL_Select_Query = "SELECT * FROM results ORDER BY result_id DESC LIMIT 1000"
                Cursor.execute(PSQL_Select_Query)
                return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall())

        else:
            return redirect(url_for('no_method'))

    else:
        return redirect(url_for('no_session'))

def check_security_requirements(Password):

    if not len(Password) >= 8:
        return False

    else:
        Lower = any(Letter.islower() for Letter in Password)
        Upper = any(Letter.isupper() for Letter in Password)
        Digit = any(Letter.isdigit() for Letter in Password)

        if not Upper or not Lower or not Digit:
            return False

        else:
            Special_Character_Regex = re.search('[\@\_\-\!\#\$\%\^\&\*\(\)\~\`\<\>\]\[\}\{\|\:\;\'\"\/\?\.\,\+\=]+', Password)

            if not Special_Character_Regex:
                return False

            else:
                return True

@app.route('/account', methods=['GET', 'POST'])
def account():

    if session.get('user'):

        if request.method == 'POST' or request.method == 'GET':

            if request.method == 'POST':

                try:
                    Current_Password = request.form['Current_Password']
                    PSQL_Select_Query = 'SELECT * FROM users WHERE username = %s'
                    Cursor.execute(PSQL_Select_Query, (session.get('user'),))
                    User = Cursor.fetchone()

                    Current_Password_Check = check_password_hash(User[2], Current_Password)

                    if Current_Password_Check != True:
                        return render_template('account.html', username=session.get('user'),
                                               error="Current Password is incorrect.")

                    else:

                        if request.form['New_Password'] != request.form['New_Password_Retype']:
                            return render_template('account.html', username=session.get('user'),
                                                   error="Please make sure the \"New Password\" and \"Retype Password\" fields match.")

                        else:
                            Password_Security_Requirements_Check = check_security_requirements(
                                request.form['New_Password'])

                            if Password_Security_Requirements_Check == False:
                                return render_template('account.html', username=session.get('user'), requirement_error=[
                                    "The supplied password does not meet security requirements. Please make sure the following is met:",
                                    "- The password is longer that 8 characters.",
                                    "- The password contains 1 or more UPPERCASE and 1 or more lowercase character.",
                                    "- The password contains 1 or more number.",
                                    "- The password contains one or more special character. Ex. @."])

                            password = generate_password_hash(request.form['New_Password'])
                            PSQL_Update_Query = 'UPDATE users SET password = %s WHERE user_id = %s'
                            Cursor.execute(PSQL_Update_Query, (password, User[0],))
                            Connection.commit()
                            return render_template('account.html', username=session.get('user'), message="Password changed.")

                except:
                    return render_template('account.html', username=session.get('user'), error="Password not updated due to bad request.")

            return render_template('account.html', username=session.get('user'))

        else:
            return redirect(url_for('no_method'))

    else:
        return redirect(url_for('no_session'))

if __name__ == '__main__':
    formatter = logging.Formatter("[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")
    handler = RotatingFileHandler('Scrummage.log', maxBytes=10000, backupCount=5)
    handler.setLevel(logging.INFO)
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.secret_key = os.urandom(24)
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)