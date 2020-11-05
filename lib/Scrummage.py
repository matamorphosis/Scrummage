#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: matamorphosis
# License: GPL-3.0

if __name__ == '__main__':

    try:
        from flask import Flask, render_template, json, request, redirect, url_for, session, send_from_directory, jsonify
        from flask_compress import Compress
        from signal import signal, SIGINT
        from functools import wraps
        from datetime import datetime, timedelta
        from werkzeug.security import generate_password_hash, check_password_hash
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from crontab import CronTab
        from logging.handlers import RotatingFileHandler
        from ratelimiter import RateLimiter
        import os, re, plugin_caller, getpass, time, sys, threading, html, secrets, jwt, matplotlib, logging, importlib, plugins.common.Connectors as Connectors, plugins.common.General as General

        Valid_Plugins = ["Ahmia Darkweb Search", "Blockchain - Bitcoin Address Search",
                         "Blockchain - Bitcoin Cash Address Search", "Blockchain - Ethereum Address Search",
                         "Blockchain - Bitcoin Transaction Search", "Blockchain - Bitcoin Cash Transaction Search",
                         "Blockchain - Ethereum Transaction Search", "Blockchain - Monero Transaction Search",
                         "Builtwith Search", "BSB Search", "Business Search - American Central Index Key",
                         "Business Search - American Company Name", "Business Search - Australian Business Number",
                         "Business Search - Australian Company Name", "Business Search - Canadian Business Number",
                         "Business Search - Canadian Company Name", "Business Search - New Zealand Business Number",
                         "Business Search - New Zealand Company Name",
                         "Business Search - United Kingdom Business Number",
                         "Business Search - United Kingdom Company Name", "Certificate Transparency - SSLMate",
                         "Certificate Transparency - CRT.sh", "Craigslist Search", "Default Password Search",
                         "DNS Reconnaissance Search", "Doing Business Search", "Domain Fuzzer - All Extensions",
                         "Domain Fuzzer - Punycode (Latin Comprehensive)", "Domain Fuzzer - Punycode (Latin Condensed)",
                         "Domain Fuzzer - Punycode (Asian)", "Domain Fuzzer - Punycode (Middle Eastern)",
                         "Domain Fuzzer - Punycode (Native American)", "Domain Fuzzer - Punycode (North African)",
                         "Domain Fuzzer - Global Domain Suffixes", "Domain Fuzzer - Regular Domain Suffixes",
                         "DuckDuckGo Search", "Ebay Search", "Flickr Search", "Google Search",
                         "Have I Been Pwned - Password Search", "Have I Been Pwned - Email Search",
                         "Have I Been Pwned - Breach Search", "Have I Been Pwned - Account Search",
                         "Hunter Search - Domain", "Hunter Search - Email", "IP Stack Search",
                         "Instagram - Location Search", "Instagram - Media Search", "Instagram - Tag Search",
                         "Instagram - User Search", "iTunes Store Search", "Library Genesis Search", "Naver Search",
                         "Phishstats Search", "Google Play Store Search", "Pinterest - Board Search",
                         "Pinterest - Pin Search", "Reddit Search", "RSS Feed Search", "Shodan Search - Domain",
                         "Shodan Search - Query", "Threat Crowd - Antivirus Search", "Threat Crowd - Domain Search",
                         "Threat Crowd - Email Search", "Threat Crowd - IP Address Search",
                         "Threat Crowd - Virus Report Search", "Torrent Search", "Twitter Scraper", "Username Search",
                         "Vehicle Registration Search", "Vkontakte - User Search", "Vkontakte - Group Search",
                         "Vulners Search", "Windows Store Search", "Yandex Search", "YouTube Search"]
        Plugins_without_Limit = ["BSB Search", "Blockchain - Monero Transaction Search",
                                 "Business Search - American Central Index Key",
                                 "Business Search - Australian Business Number",
                                 "Business Search - Canadian Business Number",
                                 "Business Search - New Zealand Business Number",
                                 "Business Search - United Kingdom Business Number", "Builtwith Search",
                                 "Certificate Transparency - SSLMate", "Certificate Transparency - CRT.sh",
                                 "DNS Reconnaissance Search", "Doing Business Search", "Domain Fuzzer - All Extensions",
                                 "Domain Fuzzer - Punycode (Latin Comprehensive)",
                                 "Domain Fuzzer - Punycode (Latin Condensed)", "Domain Fuzzer - Punycode (Asian)",
                                 "Domain Fuzzer - Punycode (Middle Eastern)",
                                 "Domain Fuzzer - Punycode (Native American)",
                                 "Domain Fuzzer - Punycode (North African)", "Domain Fuzzer - Global Domain Suffixes",
                                 "Domain Fuzzer - Regular Domain Suffixes", "Have I Been Pwned - Email Search",
                                 "Have I Been Pwned - Breach Search", "Have I Been Pwned - Password Search",
                                 "IP Stack Search", "Instagram - Media Search", "Pinterest - Pin Search", "Shodan Search - Domain",
                                 "Threat Crowd - Antivirus Search", "Threat Crowd - Domain Search",
                                 "Threat Crowd - Email Search", "Threat Crowd - IP Address Search",
                                 "Threat Crowd - Virus Report Search", "Vehicle Registration Search"]
        API_Plugins = {"Business Search - United Kingdom Business Number": "plugins.UK_Business_Search",
                       "Business Search - United Kingdom Company Name": "plugins.UK_Business_Search", "Certificate Transparency - SSLMate": "plugins.Certificate_Transparency_SSLMate",
                       "Craigslist Search": "plugins.Craigslist_Search", "Ebay Search": "plugins.Ebay_Search", "Flickr Search": "plugins.Flickr_Search",
                       "Google Search": "plugins.Google_Search", "Have I Been Pwned - Password Search": "plugins.Have_I_Been_Pwned", "Have I Been Pwned - Email Search": "plugins.Have_I_Been_Pwned",
                         "Have I Been Pwned - Breach Search": "plugins.Have_I_Been_Pwned", "Have I Been Pwned - Account Search": "plugins.Have_I_Been_Pwned", "Hunter Search - Domain": "plugins.Hunter_Search", "Hunter Search - Email": "plugins.Hunter_Search", "Naver Search": "plugins.Naver_Search",
                       "Pinterest - Board Search": "plugins.Pinterest_Search", "Pinterest - Pin Search": "plugins.Pinterest_Search",
                       "Reddit Search": "plugins.Reddit_Search", "Shodan Search - Domain": "plugins.Shodan_Search", "Shodan Search - Query": "plugins.Shodan_Search",
                       "Twitter Scraper": "plugins.Twitter_Scraper", "Vulners Search": "plugins.Vulners_Search", "Yandex Search": "plugins.Yandex_Search", "YouTube Search": "plugins.YouTube_Search", "IP Stack Search": "plugins.IPStack_Search"}
        Bad_Characters = ["|", "&", "?", "\\", "\"", "\'", "[", "]", ">", "<", "~", "`", ";", "{", "}", "%", "^", "--", "++", "+", "'", "(", ")", "*", "="]
        Finding_Types = ["Darkweb Link", "Company Details", "Blockchain - Address", "Blockchain - Transaction",
                         "BSB Details", "Certificate", "Search Result", "Credentials", "Domain Information",
                         "Social Media - Media", "Social Media - Page", "Social Media - Person", "Social Media - Group",
                         "Social Media - Place", "Application", "Account", "Account Source", "Publication", "Phishing",
                         "Forum", "News Report", "Torrent", "Vehicle Details", "Domain Spoof", "Exploit",
                         "Economic Details", "Virus", "Virus Report", "Web Application Architecture", "IP Address Information"]
        Result_Filters = ["Result ID", "Task ID", "Title", "Plugin", "Status", "Domain", "Link", "Created At", "Updated At", "Result Type"]
        Task_Filters = ["Task ID", "Query", "Plugin", "Description", "Frequency", "Task Limit", "Status", "Created At", "Updated At"]
        Event_Filters = ["Event ID", "Description", "Created At"]
        Account_Filters = ["User ID", "Username", "Blocked", "Is Admin"]
        Version = "3.0"
        Permit_Screenshots = True

        try:
            File_Path = os.path.dirname(os.path.realpath('__file__'))
            app = Flask(__name__, instance_path=os.path.join(File_Path, 'static/protected'))
            Compress(app)
            app.config.update(
                SESSION_COOKIE_SECURE=True,
                SESSION_COOKIE_HTTPONLY=True,
                SESSION_COOKIE_SAMESITE='Strict',
            )
            app.permanent_session_lifetime = timedelta(minutes=5)

        except:
            app.logger.fatal(f'{General.Date()} Startup error, ensure all necessary libraries are imported and installed.')
            sys.exit()

        def Load_Web_App_Configuration():

            try:
                File_Dir = os.path.dirname(os.path.realpath('__file__'))
                Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')
                logging.info(f"{General.Date()} Loading web application's configuration data.")

                with open(Configuration_File) as JSON_File:
                    Configuration_Data = json.load(JSON_File)
                    WA_Details = Configuration_Data['web-app']
                    WA_Debug = WA_Details['debug']
                    WA_Host = WA_Details['host']
                    WA_Port = WA_Details['port']
                    WA_Cert_File = WA_Details['certificate-file']
                    WA_Key_File = WA_Details['key-file']
                    WA_API_Secret = WA_Details['api-secret']
                    WA_API_Validity_Limit = int(WA_Details['api-validity-minutes'])
                    WA_API_Max_Calls = int(WA_Details['api-max-calls'])
                    WA_API_Period = int(WA_Details['api-period-in-seconds'])

                if WA_API_Validity_Limit < 60:
                    sys.exit("[-] API Key Validity Limit too short. Minimum should be 60 minutes.")

                if WA_Host and WA_Port and WA_Cert_File and WA_Key_File and WA_API_Secret and WA_API_Validity_Limit and WA_API_Max_Calls and WA_API_Period:
                    return [WA_Debug, WA_Host, WA_Port, WA_Cert_File, WA_Key_File, WA_API_Secret, WA_API_Validity_Limit, WA_API_Max_Calls, WA_API_Period]

                else:
                    return None

            except Exception as e:
                logging.warning(f"{General.Date()} {str(e)}")
                sys.exit()

        Application_Details = Load_Web_App_Configuration()
        API_Secret = Application_Details[5]
        API_Validity_Limit = Application_Details[6]
        API_Max_Calls = Application_Details[7]
        API_Period = Application_Details[8]

        def handler(signal_received, frame):
            print('[i] CTRL-C detected. Shutting program down.')
            Connection.close()
            sys.exit()

        signal(SIGINT, handler)
        formatter = logging.Formatter("[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")
        handler = RotatingFileHandler('Scrummage.log', maxBytes=10000, backupCount=5)
        handler.setLevel(logging.INFO)
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)
        app.secret_key = os.urandom(24)

        try:
            Connection = Connectors.Load_Main_Database()
            Cursor = Connection.cursor()

        except:
            app.logger.fatal(f'{General.Date()} Failed to load main database, please make sure the database details are added correctly to the configuration, and the PostgreSQL service is running.')
            sys.exit()

        try:
            Cursor.execute('UPDATE tasks SET status = %s', ("Stopped",))
            Connection.commit()

        except:
            app.logger.fatal(f'{General.Date()} Startup error - database issue.')
            sys.exit()

        try:
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.load_cert_chain(certfile=Application_Details[3], keyfile=Application_Details[4])

        except:
            app.logger.fatal(f'{General.Date()} Error initiating SSL.')
            sys.exit()

        class User:

            def __init__(self, username, password):
                self.username = username
                self.password = password

            def authenticate(self):
                Cursor.execute('SELECT * FROM users WHERE username = %s', (self.username,))
                User_Details = Cursor.fetchone()

                if User_Details:
                    Password_Check = check_password_hash(User_Details[2], self.password)

                    if not Password_Check:

                        for char in self.password:

                            if char in Bad_Characters:
                                Message = f"Failed login attempt for the provided user ID {str(User_Details[0])} with a password that contains potentially dangerous characters."
                                app.logger.warning(Message)
                                Create_Event(Message)
                                return {"Message": True}

                        Message = f"Failed login attempt for user {str(User_Details[0])}."
                        app.logger.warning(Message)
                        Create_Event(Message)
                        return {"Message": True}

                    else:

                        if not User_Details[3]:
                            self.ID = User_Details[0]
                            self.authenticated = True
                            self.admin = User_Details[4]
                            self.API = User_Details[5]
                            return {"ID": self.ID, "Username": User_Details[1], "Admin": self.admin, "API": self.API, "Status": True}

                        else:
                            Message = f"Login attempted by user ID {str(User_Details[0])} who is currently blocked."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            return {"Message": True}

                else:

                    for char in self.username:

                        if char in Bad_Characters:
                            Message = "Failed login attempt for a provided username that contained potentially dangerous characters."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            return {"Message": True}

                        else:
                            Message = f"Failed login attempt for user {self.username}."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            return {"Message": True}

            def API_registration(self):

                def Create_JWT(self):
                    Expiry_Hours = API_Validity_Limit / 60
                    Expiry = datetime.utcnow() + timedelta(hours=Expiry_Hours)
                    payload = {"id": self.ID, "name": self.username, "iat": datetime.utcnow(), "exp": Expiry, "nonce": secrets.token_hex(32)}
                    JWT = jwt.encode(payload, API_Secret, algorithm='HS256')
                    return JWT.decode('utf-8')

                if 'authenticated' in dir(self):

                    try:

                        if self.API:
                            Decoded_Token = jwt.decode(self.API, API_Secret, algorithm='HS256')
                            return {"Key": self.API, "Message": "Current API is still valid."}

                        else:
                            API_Key = Create_JWT(self)
                            Cursor.execute('UPDATE users SET api_key = %s, api_generated_time = %s WHERE user_id = %s', (API_Key, General.Date(), self.ID,))
                            Connection.commit()
                            Message = f"New API Key generated for user ID {str(self.ID)}."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            return {"Key": API_Key, "Message": Message}

                    except jwt.ExpiredSignatureError:
                        API_Key = Create_JWT(self)
                        Cursor.execute('UPDATE users SET api_key = %s, api_generated_time = %s WHERE user_id = %s', (API_Key, General.Date(), self.ID,))
                        Connection.commit()
                        Message = f"New API Key generated for user ID {str(self.ID)}."
                        app.logger.warning(Message)
                        Create_Event(Message)
                        return {"Key": API_Key, "Message": Message}

                    except jwt.DecodeError:
                        return {"Key": None, "Message": "Failed to verify token."}

                    except jwt.InvalidTokenError:
                        return {"Key": None, "Message": "Failed to verify token."}

                else:
                    return {"Key": None, "Message": "Unauthorised."}

        def API_verification(auth_token):

            try:
                Decoded_Token = jwt.decode(auth_token, API_Secret, algorithm='HS256')
                User_ID = int(Decoded_Token['id'])
                Cursor.execute('SELECT * FROM users WHERE user_id = %s', (User_ID,))
                User_Details = Cursor.fetchone()

                if auth_token == User_Details[5]:

                    if not User_Details[3]:
                        return {"Token": True, "Admin": User_Details[4], "Username": User_Details[1], "Message": "Token verification successful."}

                    else:
                        return {"Token": False, "Admin": False, "Message": "Token blocked."}

                else:
                    return {"Token": False, "Admin": False, "Message": "Invalid token."}

            except jwt.ExpiredSignatureError:
                return {"Token": False, "Admin": False, "Message": "Token expired."}

            except jwt.DecodeError:
                return {"Token": False, "Admin": False, "Message": "Failed to decode token."}

            except jwt.InvalidTokenError:
                return {"Token": False, "Admin": False, "Message": "Invalid token."}

        def Output_API_Checker(Plugin_Name):

            try:
                In_Dict = False
                Result = None

                for API_Key, API_Value in API_Plugins.items():

                    if Plugin_Name == API_Key:
                        In_Dict = True
                        Module = importlib.import_module(API_Value)
                        Result = Module.Load_Configuration()


                if In_Dict:
                    return Result

                else:
                    return True

            except Exception as e:
                app.logger.error(e)

        def Create_Event(Description):

            try:
                Cursor.execute("INSERT INTO events (description, created_at) VALUES (%s,%s)", (Description, General.Date()))
                Connection.commit()

            except Exception as e:
                app.logger.error(e)

        @app.errorhandler(404)
        def page_not_found(e):

            try:
                return render_template('404.html', username=session.get('user')), 404

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        @app.errorhandler(405)
        @app.route('/nomethod')
        def no_method(e):

            try:
                return render_template('nomethod.html', username=session.get('user'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        app.register_error_handler(404, page_not_found)
        app.register_error_handler(405, no_method)

        @app.route('/')
        def index():

            try:

                if session.get('user'):
                    return redirect(url_for('dashboard'))

                else:
                    return render_template('index.html')

            except Exception as e:
                app.logger.error(e)
                sys.exit("[-] Failed to initialise index.html file.")

        @app.route('/login', methods=['GET', 'POST'])
        def login():

            try:

                if request.method == 'POST':

                    if 'username' in request.form and 'password' in request.form:

                        for char in request.form['username']:

                            if char in Bad_Characters:
                                return render_template('login.html', error="Login Unsuccessful.")

                        Current_User_Object = User(request.form['username'], request.form['password'])
                        Current_User = Current_User_Object.authenticate()

                        if 'Username' in Current_User and 'Status' in Current_User:
                            session['dashboard-refresh'] = 0
                            session['user_id'] = Current_User.get('ID')
                            session['user'] = Current_User.get('Username')
                            session['is_admin'] = Current_User.get('Admin')
                            session['api_key'] = Current_User.get('API')
                            session['form_step'] = 0
                            session['form_type'] = ""
                            session['task_frequency'] = ""
                            session['task_description'] = ""
                            session['task_limit'] = 0
                            session['task_query'] = ""
                            session['task_id'] = ""
                            Message = f"Successful login from {Current_User.get('Username')}."
                            app.logger.warning(Message)
                            Create_Event(Message)

                            if session.get("next_page"):
                                Redirect = session.get("next_page")
                                session["next_page"] == ""
                                return redirect(url_for(Redirect))

                            else:
                                return redirect(url_for('dashboard'))

                        elif 'Message' in Current_User:
                            return render_template('login.html', error='Login Unsuccessful.')

                        else:
                            return render_template('login.html')

                    else:
                        return render_template('login.html')

                else:
                    return render_template('login.html')

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        @app.route('/api/auth', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_auth():

            try:

                if request.is_json:
                    Content = request.get_json()

                    if 'Username' in Content and 'Password' in Content:
                        Current_User_Object = User(Content['Username'], Content['Password'])
                        Current_User = Current_User_Object.authenticate()

                        if 'API' in Current_User:
                            Current_User_API = Current_User_Object.API_registration()

                            if "Key" in Current_User_API and "Message" in Current_User_API:
                                return jsonify({"Message": Current_User_API['Message'], "Bearer Token": Current_User_API['Key']}), 200

                            else:
                                return jsonify({"Error": "Registration Unsuccessful"}), 500

                        elif 'Message' in Current_User:
                            return jsonify({"Error": "Registration Unsuccessful."}), 500

                    else:
                        return jsonify({"Error": "Invalid fields in request."}), 500

                else:
                    return jsonify({"Error": "Invalid request format."}), 500
                
            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Invalid request format."}), 500

        @app.route('/nosession')
        def no_session():

            try:
                return render_template('no_session.html')

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        @app.route('/verify_output', methods=['GET'])
        def verify_output():

            try:

                if session.get('user'):

                    if session.get('is_admin'):
                        CSV = Connectors.Load_CSV_Configuration()
                        DD = Connectors.Load_Defect_Dojo_Configuration()
                        DOCX = Connectors.Load_DOCX_Configuration()
                        Email = Connectors.Load_Email_Configuration()
                        Elastic = Connectors.Load_Elasticsearch_Configuration()
                        Main_DB = Connectors.Load_Main_Database()
                        JIRA = Connectors.Load_JIRA_Configuration()
                        RTIR = Connectors.Load_RTIR_Configuration()
                        Slack = Connectors.Load_Slack_Configuration()
                        Scumblr = Connectors.Load_Scumblr_Configuration()
                        return render_template('verify_output.html', username=session.get('user'), Configurations=[["Main Database", Main_DB], ["CSV", CSV], ["DefectDojo", DD], ["DOCX", DOCX], ["Email", Email], ["ElasticSearch", Elastic], ["JIRA", JIRA], ["RTIR", RTIR], ["Slack Channel Notification", Slack], ["Scumblr Database", Scumblr]], is_admin=session.get('is_admin'))

                    else:
                        return redirect(url_for('tasks'))

                else:
                    session["next_page"] = "verify_output"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/tasks/output/options/verify')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_verify_output():

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'GET':
                                CSV = Connectors.Load_CSV_Configuration()
                                DD = Connectors.Load_Defect_Dojo_Configuration()
                                DOCX = Connectors.Load_DOCX_Configuration()
                                Email = Connectors.Load_Email_Configuration()
                                Elastic = Connectors.Load_Elasticsearch_Configuration()
                                Main_DB = Connectors.Load_Main_Database()
                                JIRA = Connectors.Load_JIRA_Configuration()
                                RTIR = Connectors.Load_RTIR_Configuration()
                                Slack = Connectors.Load_Slack_Configuration()
                                Scumblr = Connectors.Load_Scumblr_Configuration()

                                return jsonify([{"Main Database": bool(Main_DB)}, {"CSV": bool(CSV)}, {"DefectDojo": bool(DD)}, {".DOCX": bool(DOCX)}, {"Email": bool(Email)}, {"ElasticSearch": bool(Elastic)}, {"JIRA": bool(JIRA)}, {"RTIR": bool(RTIR)}, {"Slack Channel Notification": bool(Slack)}, {"Scumblr Database": bool(Scumblr)}]), 200

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        def Screenshot_Checker():
            global Permit_Screenshots
            Chrome_Config = Connectors.Load_Chrome_Configuration()

            if all(os.path.exists(Config) for Config in Chrome_Config): 
                CHROME_PATH = Chrome_Config[0]
                CHROMEDRIVER_PATH = Chrome_Config[1]
                chrome_options = Options()
                chrome_options.add_argument("--headless")
                chrome_options.binary_location = CHROME_PATH

                try:
                    driver = webdriver.Chrome(
                        executable_path=CHROMEDRIVER_PATH,
                        options=chrome_options
                    )

                except Exception as e:

                    if "session not created" in str(e):
                        app.logger.warning(f"\033[0;31mPlease run the \"Fix_ChromeDriver.sh\" script in the installation directory to upgrade the Google Chrome Driver to be in-line with the current version of Google Chrome on this operating system, or replace it manually with the latest version from http://chromedriver.chromium.org/downloads that matches the version of Chrome installed on your system. The Chrome driver is located at {Chrome_Config[1]}. Screenshot functionality has been disabled in the meantime until this issue is resolved.\033[0m\n")
                        Permit_Screenshots = False

            else:
                app.logger.warning("\033[0;31mOne or more of the values provided to the google chrome configuration in the config.json file do not reflect real files. Screenshot functionality has been disabled in the meantime. To correct this please accurately fill out the following section in the config.json file (Example values included, please ensure these reflect real files on your system)\n\n    \"google-chrome\": {\n        \"application-path\": \"/usr/bin/google-chrome\",\n        \"chromedriver-path\": \"/usr/bin/chromedriver\"\n    },\n\033[0m")
                Permit_Screenshots = False

        def requirement(f):

            try:
                @wraps(f)
                def wrap(*args, **kwargs):

                    if session.get('user'):
                        return f(*args, **kwargs)

                    else:
                        return redirect(url_for('no_session'))

                return wrap

            except Exception as e:
                app.logger.error(e)

        @app.route('/static/protected/<path:filename>')
        @requirement
        def protected(filename):

            try:
                Risk_Level = General.Load_Web_Scrape_Risk_Configuration()

                if filename.endswith('.html') and Risk_Level == 0:
                    return render_template('restricted.html', username=session.get('user'))

                else:
                    return send_from_directory(os.path.join(app.instance_path, ''), filename)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.after_request
        def apply_caching(response):

            try:
                response.headers["X-Frame-Options"] = "SAMEORIGIN"
                response.headers["X-XSS-Protection"] = "1; mode=block"
                response.headers["X-Content-Type"] = "nosniff"
                response.headers["Server"] = ""
                response.headers["Pragma"] = "no-cache"
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, pre-check=0, post-check=0, max-age=0, s-maxage=0"
                return response

            except Exception as e:
                app.logger.error(e)

        @app.route('/api/result/screenshot/<resultid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_results_screenshot(resultid):

            try:

                if Permit_Screenshots:

                    if 'Authorization' in request.headers:
                        Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                        Authentication_Verified = API_verification(Auth_Token)

                        if Authentication_Verified["Token"]:

                            if Authentication_Verified["Admin"]:

                                if request.method == 'POST':

                                    def grab_screenshot(screenshot_id, user, Chrome_Config):
                                        Cursor.execute('SELECT link FROM results WHERE result_id = %s', (screenshot_id,))
                                        result = Cursor.fetchone()
                                        Cursor.execute('SELECT screenshot_url FROM results WHERE result_id = %s', (screenshot_id,))
                                        SS_URL = Cursor.fetchone()
                                        Cursor.execute('SELECT screenshot_requested FROM results WHERE result_id = %s', (screenshot_id,))
                                        SS_Req = Cursor.fetchone()
                                        Message = f"Screenshot requested for result number {str(screenshot_id)} by {user}."
                                        app.logger.warning(Message)
                                        Create_Event(Message)
                                        Cursor.execute('UPDATE results SET screenshot_requested = %s WHERE result_id = %s', (True, screenshot_id,))
                                        Connection.commit()

                                        if any(String in result[0] for String in Bad_Link_Strings):
                                            return redirect(url_for('results'))

                                        screenshot_file = result[0].replace("http://", "")
                                        screenshot_file = screenshot_file.replace("https://", "")

                                        if screenshot_file.endswith('/'):
                                            screenshot_file = screenshot_file[:-1]

                                        if '?' in screenshot_file:
                                            screenshot_file_list = screenshot_file.split('?')
                                            screenshot_file = screenshot_file_list[0]

                                        for replaceable_item in ['/', '?', '#', '&', '%', '$', '@', '*', '=']:
                                            screenshot_file = screenshot_file.replace(replaceable_item, '-')

                                        CHROME_PATH = Chrome_Config[0]
                                        CHROMEDRIVER_PATH = Chrome_Config[1]
                                        screenshot_file = f"{screenshot_file}.png"
                                        chrome_options = Options()
                                        chrome_options.add_argument("--headless")
                                        chrome_options.binary_location = CHROME_PATH

                                        try:
                                            driver = webdriver.Chrome(
                                                executable_path=CHROMEDRIVER_PATH,
                                                options=chrome_options
                                            )

                                        except Exception as e:

                                            if "session not created" in str(e):
                                                e = str(e).strip('\n')
                                                Message = f"Screenshot request terminated for result number {str(screenshot_id)} by application, please refer to the log."
                                                Message_E = e.replace("Message: session not created: ", "")
                                                Message_E = Message_E.replace("This version of", "The installed version of")
                                                app.logger.warning(f"Screenshot Request Error: {Message_E}.")
                                                app.logger.warning(f"Kindly replace the Chrome Web Driver, located at {Chrome_Config[1]}, with the latest one from http://chromedriver.chromium.org/downloads that matches the version of Chrome installed on your system.")
                                                Create_Event(Message)
                                                Cursor.execute('UPDATE results SET screenshot_requested = %s WHERE result_id = %s', (False, screenshot_id,))
                                                Connection.commit()
                                            
                                            return 0

                                        driver.get(result[0])
                                        driver.implicitly_wait(10)
                                        time.sleep(10)
                                        total_height = driver.execute_script("return document.body.scrollHeight")
                                        driver.set_window_size(1920, total_height)
                                        driver.save_screenshot(f"static/protected/screenshots/{screenshot_file}")
                                        driver.close()
                                        Cursor.execute('UPDATE results SET screenshot_url = %s WHERE result_id = %s', (screenshot_file, screenshot_id,))
                                        Connection.commit()

                                    ss_id = int(resultid)
                                    Chrome_Config = Connectors.Load_Chrome_Configuration()

                                    if all(os.path.exists(Config) for Config in Chrome_Config):
                                        Cursor.execute('SELECT screenshot_url FROM results WHERE result_id = %s', (screenshot_id,))
                                        SS_URL = Cursor.fetchone()
                                        Cursor.execute('SELECT screenshot_requested FROM results WHERE result_id = %s', (screenshot_id,))
                                        SS_Req = Cursor.fetchone()

                                        if not SS_URL[0] and not SS_Req[0]:
                                            Thread_1 = threading.Thread(target=grab_screenshot, args=(ss_id, Authentication_Verified["Username"], Chrome_Config))
                                            Thread_1.start()
                                            return jsonify({"Message": f"Successfully requested screenshot for {str(ss_id)}."}), 200

                                        else:
                                            jsonify({"Error": f"Screenshot already requested for result id {str(ss_id)}."})

                                    else:
                                        return jsonify({"Error": "Screenshot request terminated. Google Chrome and/or Chrome Driver have either not been installed or configured properly."}), 500

                                else:
                                    return jsonify({"Error": "Method not allowed."}), 500

                            else:
                                return jsonify({"Error": "Insufficient privileges."}), 500

                        else:

                            if Authentication_Verified["Message"]:
                                return jsonify({"Error": Authentication_Verified["Message"]}), 500

                            else:
                                return jsonify({"Error": "Unauthorised."}), 500

                    else:
                        return jsonify({"Error": "Missing Authorization header."}), 500

                else:
                    return jsonify({"Error": "Screenshots currently disabled due to a mismatch between Google Chrome and Chrome Driver versions on the server."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/results/screenshot/<resultid>', methods=['POST'])
        def screenshot(resultid):

            try:
                Bad_Link_Strings = ['.onion', 'general-insurance.coles.com.au', 'magnet:?xt=urn:btih:']

                if session.get('user') and session.get('is_admin'):

                    if Permit_Screenshots:

                        def grab_screenshot(screenshot_id, user, Chrome_Config):
                            Cursor.execute('SELECT link FROM results WHERE result_id = %s', (screenshot_id,))
                            result = Cursor.fetchone()
                            Cursor.execute('SELECT screenshot_url FROM results WHERE result_id = %s', (screenshot_id,))
                            SS_URL = Cursor.fetchone()
                            Cursor.execute('SELECT screenshot_requested FROM results WHERE result_id = %s', (screenshot_id,))
                            SS_Req = Cursor.fetchone()

                            if not SS_URL[0] and not SS_Req[0]:
                                Message = f"Screenshot requested for result number {str(screenshot_id)} by {user}."
                                app.logger.warning(Message)
                                Create_Event(Message)
                                Cursor.execute('UPDATE results SET screenshot_requested = %s WHERE result_id = %s', (True, screenshot_id,))
                                Connection.commit()

                                if any(String in result[0] for String in Bad_Link_Strings):
                                    return redirect(url_for('results'))

                                screenshot_file = result[0].replace("http://", "")
                                screenshot_file = screenshot_file.replace("https://", "")

                                if screenshot_file.endswith('/'):
                                    screenshot_file = screenshot_file[:-1]

                                if '?' in screenshot_file:
                                    screenshot_file_list = screenshot_file.split('?')
                                    screenshot_file = screenshot_file_list[0]

                                for replaceable_item in ['/', '?', '#', '&', '%', '$', '@', '*', '=']:
                                    screenshot_file = screenshot_file.replace(replaceable_item, '-')

                                CHROME_PATH = Chrome_Config[0]
                                CHROMEDRIVER_PATH = Chrome_Config[1]
                                screenshot_file = f"{screenshot_file}.png"
                                chrome_options = Options()
                                chrome_options.add_argument("--headless")
                                chrome_options.binary_location = CHROME_PATH

                                try:
                                    driver = webdriver.Chrome(
                                        executable_path=CHROMEDRIVER_PATH,
                                        options=chrome_options
                                    )

                                except Exception as e:

                                    if "session not created" in str(e):
                                        e = str(e).strip('\n')
                                        Message = f"Screenshot request terminated for result number {str(screenshot_id)} by application, please refer to the log."
                                        Message_E = e.replace("Message: session not created: ", "")
                                        Message_E = Message_E.replace("This version of", "The installed version of")
                                        app.logger.warning(f"Screenshot Request Error: {Message_E}.")
                                        app.logger.warning(f"Kindly replace the Chrome Web Driver, located at {Chrome_Config[1]}, with the latest one from http://chromedriver.chromium.org/downloads that matches the version of Chrome installed on your system.")
                                        Create_Event(Message)
                                        Cursor.execute('UPDATE results SET screenshot_requested = %s WHERE result_id = %s', (False, screenshot_id,))
                                        Connection.commit()
                                    
                                    return 0

                                driver.get(result[0])
                                driver.implicitly_wait(10)
                                time.sleep(10)
                                total_height = driver.execute_script("return document.body.scrollHeight")
                                driver.set_window_size(1920, total_height)
                                driver.save_screenshot(f"static/protected/screenshots/{screenshot_file}")
                                driver.close()
                                Cursor.execute('UPDATE results SET screenshot_url = %s WHERE result_id = %s', (screenshot_file, screenshot_id,))
                                Connection.commit()

                            else:
                                app.logger.warning(f"Screenshot already requested for result id {str(ss_id)}.")

                        ss_id = int(resultid)
                        Chrome_Config = Connectors.Load_Chrome_Configuration()

                        if all(os.path.exists(Config) for Config in Chrome_Config):
                            Thread_1 = threading.Thread(target=grab_screenshot, args=(ss_id, str(session.get('user')), Chrome_Config))
                            Thread_1.start()

                        else:
                            app.logger.warning(f"Either Google Chrome or Chrome Driver have not been installed / configured. Screenshot request terminated.")                    

                    else:
                        app.logger.warning("Screenshots currently disabled due to a mismatch between Google Chrome and Chrome Driver versions on the server.")

                    return redirect(url_for('results'))

                else:
                    session["next_page"] = "results"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/dashboard', methods=['GET'])
        def dashboard():

            try:

                if session.get('user'):
                    labels = Finding_Types
                    colors_blue = ["#00162b", "#001f3f", "#002952", "#003366", "#003d7a", "#00478d", "#0050a1", "#005ab4", "#0064c8", "#006edc", "#0078ef", "#0481ff", "#188bff", "#2b95ff", "#3f9fff", "#52a9ff", "#66b3ff", "#7abcff", "#8dc6ff", "#a1d0ff", "#b4daff", "#c8e4ff", "#dcedff", "#eff7ff"]
                    colors_red = ["#2b0000", "#3f0000", "#520000", "#660000", "#7a0000", "#8d0000", "#a10000", "#b40000", "#c80000", "#dc0000", "#ef0000", "#ff0404", "#ff1818", "#ff2b2b", "#ff3f3f", "#ff5252", "#ff6666", "#ff7a7a", "#ff8d8d", "#ffa1a1"]
                    colors_original = colors_blue + colors_red
                    colors = colors_original[:len(labels)]
                    Mixed_Options = ['Inspecting', 'Reviewing']
                    PSQL_Select_Query_1 = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
                    PSQL_Select_Query_2 = 'SELECT count(*) FROM results WHERE result_type = %s AND status = ANY (%s);'
                    open_values = []
                    closed_values = []
                    mixed_values = []
                    Use_Open = True
                    Use_Closed = True
                    Use_Mixed = True

                    for Finding_Type in Finding_Types:
                        Cursor.execute(PSQL_Select_Query_1, ("Open", Finding_Type,))
                        current_open_results = Cursor.fetchall()
                        open_values.append([current_open_results[0][0]])
                        Cursor.execute(PSQL_Select_Query_1, ("Closed", Finding_Type,))
                        current_closed_results = Cursor.fetchall()
                        closed_values.append([current_closed_results[0][0]])
                        Cursor.execute(PSQL_Select_Query_2, (Finding_Type, Mixed_Options,))
                        current_mixed_results = Cursor.fetchall()
                        mixed_values.append([current_mixed_results[0][0]])

                    most_common_tasks_labels = []
                    most_common_tasks_values = []
                    Cursor.execute("SELECT plugin, COUNT(*) AS counted FROM tasks WHERE plugin IS NOT NULL GROUP BY plugin ORDER BY counted DESC, plugin LIMIT 10;")
                    most_common_tasks = Cursor.fetchall()

                    for mc_task in most_common_tasks:
                        most_common_tasks_labels.append(mc_task[0])
                        most_common_tasks_values.append(mc_task[1])

                    if all(open_item == [0] for open_item in open_values):
                        Use_Open = False

                    if all(closed_item == [0] for closed_item in closed_values):
                        Use_Closed = False

                    if all(mixed_item == [0] for mixed_item in mixed_values):
                        Use_Mixed = False

                    if most_common_tasks:
                        return render_template('dashboard.html', username=session.get('user'), max=17000, open_set=[open_values, labels, colors], closed_set=[closed_values, labels, colors], mixed_set=[mixed_values, labels, colors], bar_set=[most_common_tasks_labels, most_common_tasks_values, colors_original[:len(most_common_tasks_values)]], Use_Open=Use_Open, Use_Closed=Use_Closed, Use_Mixed=Use_Mixed, refreshrate=session.get('dashboard-refresh'), version=Version)

                    else:
                        return render_template('dashboard.html', username=session.get('user'), max=17000, open_set=[open_values, labels, colors], closed_set=[closed_values, labels, colors], mixed_set=[mixed_values, labels, colors], refreshrate=session.get('dashboard-refresh'), version=Version, Use_Open=Use_Open, Use_Closed=Use_Closed, Use_Mixed=Use_Mixed)

                else:
                    session["next_page"] = "dashboard"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)

        @app.route('/dashboard/set-refresh', methods=['POST'])
        def dashboard_refresh():

            try:

                if session.get('user'):

                    if 'setrefresh' in request.form and 'interval' in request.form:
                        approved_refresh_rates = [0, 5, 10, 15, 20, 30, 60]
                        refresh_rate = int(request.form['interval'])

                        if refresh_rate in approved_refresh_rates:
                            session['dashboard-refresh'] = refresh_rate
                            return redirect(url_for('dashboard'))

                        else:
                            return redirect(url_for('dashboard'))

                    else:
                        return redirect(url_for('dashboard'))

                else:
                    session["next_page"] = "dashboard"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)

        @app.route('/api/dashboard', methods=['GET'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_dashboard():

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)
                    Mixed_Options = ['Inspecting', 'Reviewing']
                    PSQL_Select_Query_1 = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s'
                    PSQL_Select_Query_2 = 'SELECT count(*) FROM results WHERE result_type = %s AND status = ANY (%s);'

                    if Authentication_Verified.get("Token"):
                        open_values = {}
                        closed_values = {}
                        mixed_values = {}

                        for Finding_Type in Finding_Types:
                            Cursor.execute(PSQL_Select_Query_1, ("Open", Finding_Type,))
                            current_open_results = Cursor.fetchall()
                            open_values[Finding_Type] = current_open_results[0][0]
                            Cursor.execute(PSQL_Select_Query_1, ("Closed", Finding_Type,))
                            current_closed_results = Cursor.fetchall()
                            closed_values[Finding_Type] = current_closed_results[0][0]
                            Cursor.execute(PSQL_Select_Query_2, (Finding_Type, Mixed_Options,))
                            current_mixed_results = Cursor.fetchall()
                            mixed_values[Finding_Type] = current_mixed_results[0][0]

                        Cursor.execute("""SELECT plugin, COUNT(*) AS counted FROM tasks WHERE plugin IS NOT NULL GROUP BY plugin ORDER BY counted DESC, plugin LIMIT 10;""")
                        most_common_tasks = Cursor.fetchall()
                        data = {"Open Issues": open_values, "Closed Issues": closed_values, "Issues Under Review or inspection": mixed_values, "Most Common Tasks": [{}]}
                        
                        for mc_task in most_common_tasks:
                            data["Most Common Tasks"][0][mc_task[0]] = mc_task[1]

                        return jsonify(data), 200

                    else:

                        if Authentication_Verified.get("Message"):
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/dropsession')
        def dropsession():

            try:

                if session.get('user'):
                    username = session.get('user')
                    session.pop('user', None)
                    session.pop('is_admin', False)
                    Message = f"Session for user: {username} terminated."
                    app.logger.warning(Message)
                    Create_Event(Message)

                return render_template('index.html', loggedout=True)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        @app.route('/events', methods=['GET'])
        def events():

            try:

                if session.get('user'):
                    Cursor.execute("SELECT * FROM events ORDER BY event_id DESC LIMIT 1000")
                    events = Cursor.fetchall()
                    return render_template('events.html', username=session.get('user'), events=events, Event_Filters=Event_Filters)

                else:
                    session["next_page"] = "events"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('events'))

        @app.route('/events/filtered', methods=['GET', 'POST'])
        def events_filtered():

            try:
            
                if session.get('user'):
                
                    if 'filter' in request.args and 'filtervalue' in request.args:
                        Filter = str(request.args['filter'])
                        Filter_Value = str(request.args['filtervalue'])

                        if "ID" in Filter:
                            Filter_Value = int(Filter_Value)

                        if Filter in Event_Filters:
                            Converted_Filter = Filter.lower().replace(" ", "_")
                        
                            if type(Filter_Value) == int:
                                Cursor.execute(f"SELECT * FROM events WHERE {Converted_Filter} = {Filter_Value} ORDER BY event_id DESC LIMIT 1000")

                            elif (type(Filter_Value) == str and not any(char in Filter_Value for char in Bad_Characters)):
                                Cursor.execute(f"SELECT * FROM events WHERE {Converted_Filter} = \'{Filter_Value}\' ORDER BY event_id DESC LIMIT 1000")
                            
                            else:
                                return redirect(url_for('events'))

                            return render_template('events.html', username=session.get('user'), events=Cursor.fetchall(), Filter_Name=Filter, Filter_Value=Filter_Value, Finding_Types=Finding_Types, Event_Filters=Event_Filters)

                        else:
                            return redirect(url_for('events'))

                    else:
                        return redirect(url_for('events'))

                else:
                    session["next_page"] = "events_filtered"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('events'))

        @app.route('/api/events')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_event_details():

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified.get("Token"):

                        if request.method == 'GET':

                            if request.is_json:
                                Content = request.get_json()
                                data = {}
                                Safe_Content = {}

                                for Item in ["ID", "Description", "Created At"]:

                                    if Item in Content:

                                        if any(char in Item for char in Bad_Characters):
                                            return jsonify({"Error": f"Bad characters detected in the {Item} field."}), 500

                                        if Item == "ID":

                                            if type(Content[Item]) != int:
                                                return jsonify({"Error": f"The ID provided is not an integer."}), 500

                                            Safe_Content["event_id"] = Content[Item]

                                        elif " " in Item:
                                            Safe_Content[Item.lower().replace(" ", "_")] = Content[Item]

                                        else:
                                            Safe_Content[Item.lower()] = Content[Item]

                                if len(Safe_Content) > 1:
                                    Select_Query = "SELECT * FROM events WHERE "

                                    for Item_Key, Item_Value in sorted(Safe_Content.items()):
                                        Select_Query += f"{Item_Key} = '{Item_Value}'"

                                        if Item_Key != sorted(Safe_Content.keys())[-1]:
                                            Select_Query += " and "

                                        else:
                                            Select_Query += ";"

                                    Cursor.execute(Select_Query)

                                elif len(Safe_Content) == 1:
                                    Key = list(Safe_Content.keys())[0]
                                    Val = list(Safe_Content.values())[0]
                                    Cursor.execute(f"SELECT * FROM events WHERE {Key} = '{Val}';")

                                else:
                                    return jsonify({"Error": "No valid fields found in request."}), 500

                                for Event in Cursor.fetchall():
                                    data[Event[0]] = [{"Description": Event[1], "Created Timestamp": Event[2]}]

                                return jsonify(data), 200

                            else:
                                data = {}
                                Cursor.execute('SELECT * FROM events ORDER BY event_id DESC LIMIT 100')

                                for Event in Cursor.fetchall():
                                    data[Event[0]] = [{"Description": Event[1], "Created Timestamp": Event[2]}]

                                return jsonify(data), 200

                        else:
                            return jsonify({"Error": "Method not allowed."}), 500

                    else:

                        if Authentication_Verified.get("Message"):
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except:
                return jsonify({"Error": "Unknown Exception Occurred."}), 500

        @app.route('/api/endpoints')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_endpoints():

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified.get("Token"):

                        if request.method == 'GET':

                            if Authentication_Verified["Admin"]:
                                Auth_Endpoint = {'POST': {"Obtain API Key": {"Endpoint": "/api/auth", "Admin rights required": False, "Fields": {"Username": {"Attributes": {"Required": True, "Type": "String"}}, "Password": {"Attributes": {"Required": True, "Type": "String"}}}}}}
                                Dashboard_Endpoints = {"GET": {"Retrieve dashboard statistics": {"Endpoint": "api/dashboard", "Admin rights required": False}}}
                                Result_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/results", "Admin rights required": False, "Optional Search Filters": {"ID": "Integer", "Associated Task ID": "Integer", "Title": "String", "Plugin": "String", "Domain": "String", "Link": "String", "Screenshot URL": "String", "Status": "String", "Output Files": "String", "Result Type": "String", "Screenshot Requested": "String", "Created At": "String - Timestamp", "Updated At": "String - Timestamp"}}}, "POST": {"Create a new manual result": {"Endpoint": "/api/result/new", "Admin rights required": True, "Fields": {"Name": {"Attributes": {"Required": True, "Type": "String"}}, "URL": {"Attributes": {"Required": True, "Type": "String"}}, "Type": {"Attributes": {"Required": True, "Type": "String"}}}}, "Delete a result": {"Endpoint": "/api/result/delete/<result_id>", "Admin rights required": True}, "Re-open a result": {"Endpoint": "/api/result/changestatus/open/<result_id>", "Admin rights required": True}, "Label a result as under inspection": {"Endpoint": "/api/result/changestatus/inspect/<result_id>", "Admin rights required": True}, "Label a result as under review": {"Endpoint": "/api/result/changestatus/review/<result_id>", "Admin rights required": True}, "Close a result": {"Endpoint": "/api/result/changestatus/close/<result_id>", "Admin rights required": True}}}
                                Task_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/tasks", "Admin rights required": False, "Optional Search Filters": {"ID": "Integer", "Query": "String", "Plugin": "String", "Description": "String", "Frequency": "String - Cronjob", "Limit": "Integer", "Status": "String", "Created At": "String - Timestamp", "Updated At": "String - Timestamp"}}, "Show which output options are enabled for receiving task results": {"Endpoint": "/api/tasks/output/options/verify", "Admin rights required": True}}, "POST": {"Create a new task": {"Endpoint": "/api/task/new", "Admin rights required": True, "Fields": {"Task Type": {"Required": True, "Type": "String"}, "Query": {"Required": True, "Type": "String"}, "Frequency": {"Required": False, "Type": "String - Cronjob"}, "Description": {"Required": False, "Type": "String"}, "Limit": {"Required": False, "Type": "Integer"}}}, "Edit a task": {"Endpoint": "/api/task/edit/<task_id>", "Admin rights required": True, "Fields": {"Task Type": {"Required": True, "Type": "String"}, "Query": {"Required": True, "Type": "String"}, "Frequency": {"Required": False, "Type": "String - Cronjob"}, "Description": {"Required": False, "Type": "String"}, "Limit": {"Required": False, "Type": "Integer"}}}, "Run a task": {"Endpoint": "/api/task/run/<task_id>", "Admin rights required": True}, "Duplicate a task": {"Endpoint": "/api/task/duplicate/<task_id>", "Admin rights required": True}, "Delete a task": {"Endpoint": "/api/task/delete/<task_id>", "Admin rights required": True}}}
                                Event_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/events", "Admin rights required": False, "Optional Search Filters": {"ID": "Integer", "Description": "String", "Created At": "String - Timestamp"}}}}
                                Account_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/accounts", "Admin rights required": True, "Optional Search Filters": {"ID": "Integer", "Username": "String", "Blocked": "Boolean", "Administrative Rights": "Boolean"}}}, "POST": {"Create new account": {"Endpoint": "/api/account/new", "Admin rights required": True, "Fields": {"Username": {"Attributes": {"Required": True, "Type": "String"}}, "Password": {"Attributes": {"Required": True, "Type": "String"}}, "Password Retype": {"Attributes": {"Required": True, "Type": "String"}}}}, "Delete account": {"Endpoint": "/api/account/delete/<account_id>", "Admin rights required": True}, "Disable account": {"Endpoint": "/api/account/disable/<account_id>", "Admin rights required": True}, "Enable account": {"Endpoint": "/api/account/enable/<account_id>", "Admin rights required": True}, "Give account administrative rights": {"Endpoint": "/api/account/promote/<account_id>", "Admin rights required": True}, "Strip account of administrative rights": {"Endpoint": "/api/account/demote/<account_id>", "Admin rights required": True}, "Change any user's password": {"Endpoint": "/api/account/password/change/<account_id>", "Admin rights required": True, "Fields": {"Password": {"Attributes": {"Required": True, "Type": "String"}}, "Password Retype": {"Attributes": {"Required": True, "Type": "String"}}}}}}
                                return jsonify({"Endpoints": {"API": {"GET": {"Endpoint Checking": "/api/endpoints", "Admin rights required": False}}, "Authentication": Auth_Endpoint, "Dashboard": Dashboard_Endpoints, "Tasks": Task_Endpoints, "Results": Result_Endpoints, "Events": Event_Endpoints, "User Management": Account_Endpoints}}), 200

                            else:
                                Auth_Endpoint = {'POST': {"Obtain API Key": {"Endpoint": "/api/auth", "Fields": {"Username": {"Attributes": {"Required": True, "Type": "String"}}, "Password": {"Attributes": {"Required": True, "Type": "String"}}}}}}
                                Dashboard_Endpoints = {"GET": {"Retrieve dashboard statistics": "api/dashboard"}}
                                Result_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/results", "Optional Search Filters": {"ID": "Integer", "Associated Task ID": "Integer", "Title": "String", "Plugin": "String", "Domain": "String", "Link": "String", "Screenshot URL": "String", "Status": "String", "Output Files": "String", "Result Type": "String", "Screenshot Requested": "String", "Created At": "String - Timestamp", "Updated At": "String - Timestamp"}}}}
                                Task_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/tasks", "Optional Search Filters": {"ID": "Integer", "Query": "String", "Plugin": "String", "Description": "String", "Frequency": "String - Cronjob", "Limit": "Integer", "Status": "String", "Created At": "String - Timestamp", "Updated At": "String - Timestamp"}}}}
                                Event_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/events", "Optional Search Filters": {"ID": "Integer", "Description": "String", "Created At": "String - Timestamp"}}}}
                                return jsonify({"Endpoints": {"API": {"GET": {"Endpoint Checking": "/api/endpoints"}}, "Authentication": Auth_Endpoint, "Dashboard": Dashboard_Endpoints, "Tasks": Task_Endpoints, "Results": Result_Endpoints, "Events": Event_Endpoints}}), 200
                                           
                        else:
                            return jsonify({"Error": "Method not allowed."}), 500

                    else:

                        if Authentication_Verified.get("Message"):
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except:
                return jsonify({"Error": "Unknown Exception Occurred."}), 500

        @app.route('/tasks', methods=['GET', 'POST'])
        def tasks():

            try:

                if session.get('user'):
                    session['form_step'] = 0
                    session['form_type'] = ""
                    session['task_frequency'] = ""
                    session['task_description'] = ""
                    session['task_limit'] = 0
                    session['task_query'] = ""
                    session['task_id'] = 0
                    Cursor.execute("SELECT * FROM tasks ORDER BY task_id DESC LIMIT 1000")
                    task_results = Cursor.fetchall()
                    return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), results=task_results, Task_Filters=Task_Filters)

                else:
                    session["next_page"] = "tasks"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/tasks/filtered', methods=['GET', 'POST'])
        def tasks_filtered():

            try:
            
                if session.get('user'):
                    session['form_step'] = 0
                    session['form_type'] = ""
                    session['task_frequency'] = ""
                    session['task_description'] = ""
                    session['task_limit'] = 0
                    session['task_query'] = ""
                    session['task_id'] = 0
                
                    if 'filter' in request.args and 'filtervalue' in request.args:
                        Filter = str(request.args['filter'])
                        Filter_Value = str(request.args['filtervalue'])

                        if "ID" in Filter:
                            Filter_Value = int(Filter_Value)

                        if Filter in Task_Filters:
                            Converted_Filter = Filter.lower().replace(" ", "_")
                            Current_Bad_Chars = Bad_Characters

                            for Current_Char in [")", "(", "-", "*", "/"]:

                                if Current_Char in Current_Bad_Chars:
                                    Current_Bad_Chars.remove(Current_Char)
                        
                            if type(Filter_Value) == int:
                                Cursor.execute(f"SELECT * FROM tasks WHERE {Converted_Filter} = {Filter_Value} ORDER BY task_id DESC LIMIT 1000")

                            elif (type(Filter_Value) == str and not any(char in Filter_Value for char in Bad_Characters)):
                                Cursor.execute(f"SELECT * FROM tasks WHERE {Converted_Filter} = \'{Filter_Value}\' ORDER BY task_id DESC LIMIT 1000")
                            
                            else:
                                return redirect(url_for('tasks'))

                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), Filter_Name=Filter, Filter_Value=Filter_Value, Finding_Types=Finding_Types, Task_Filters=Task_Filters)

                        else:
                            return redirect(url_for('tasks'))

                    else:
                        return redirect(url_for('tasks'))

                else:
                    session["next_page"] = "tasks_filtered"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/task/duplicate/<taskid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_tasks_duplicate(taskid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':
                                dup_id = int(dup_id)
                                Cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (dup_id,))
                                result = Cursor.fetchone()

                                if result:
                                    Current_Timestamp = General.Date() # Variable set to create consistency in timestamps across two seperate database queries.
                                    Cursor.execute('INSERT INTO tasks (query, plugin, description, frequency, task_limit, status, created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)', (result[1], result[2], result[3], result[4], str(result[5]), "Stopped", str(Current_Timestamp), str(Current_Timestamp)))
                                    Connection.commit()

                                    if result[4]:
                                        time.sleep(1)
                                        Cursor.execute("SELECT * FROM tasks WHERE query = %s AND plugin = %s AND description = %s AND frequency = %s AND task_limit = %s AND status = %s AND created_at = %s AND updated_at = %s;", (result[1], result[2], result[3], result[4], str(result[5]), "Stopped", str(Current_Timestamp), str(Current_Timestamp),))
                                        result = Cursor.fetchone()
                                        task_id = result[0]
                                        Cron_Command = f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(task_id)}'

                                        try:
                                            my_cron = CronTab(user=getpass.getuser())
                                            job = my_cron.new(command=Cron_Command)
                                            job.setall(result[4])
                                            my_cron.write()

                                        except Exception as e:
                                            Cursor.execute('UPDATE tasks SET frequency = %s WHERE task_id = %s', ("", task_id,))
                                            Connection.commit()
                                            return jsonify({"Error": f"Failed to create cronjob. Task was still created.", "Attempted Cronjob": Cron_Command}), 500

                                        User = Authentication_Verified["Username"]
                                        Message = f"Task ID {str(dup_id)} duplicated by {User}."
                                        app.logger.warning(Message)
                                        Create_Event(Message)
                                        return jsonify({"Message": "Successfully duplicated task.", "Provided Task ID": dup_id, "New Task ID": task_id}), 200

                                    else:
                                        return jsonify({"Error": "Unable to retrieve database value."}), 500

                                else:
                                    return jsonify({"Error": f"Unable to find provided task id {str(dup_id)}."}), 500

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks/duplicate/<taskid>', methods=['POST'])
        def duplicate_task(taskid):

            try:

                if session.get('user') and session.get('is_admin'):

                    def dup_task(dup_id):
                        dup_id = int(dup_id)
                        Cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (dup_id,))
                        result = Cursor.fetchone()

                        if result:
                            Current_Timestamp = General.Date() # Variable set to create consistency in timestamps across two seperate database queries.
                            Cursor.execute('INSERT INTO tasks (query, plugin, description, frequency, task_limit, status, created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)', (result[1], result[2], result[3], result[4], str(result[5]), "Stopped", str(Current_Timestamp), str(Current_Timestamp)))
                            Connection.commit()

                            if result[4]:
                                time.sleep(1)
                                Cursor.execute("SELECT * FROM tasks WHERE query = %s AND plugin = %s AND description = %s AND frequency = %s AND task_limit = %s AND status = %s AND created_at = %s AND updated_at = %s;", (result[1], result[2], result[3], result[4], str(result[5]), "Stopped", str(Current_Timestamp), str(Current_Timestamp),))
                                result = Cursor.fetchone()
                                task_id = result[0]

                                try:
                                    my_cron = CronTab(user=getpass.getuser())
                                    job = my_cron.new(command=f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(task_id)}')
                                    job.setall(result[4])
                                    my_cron.write()

                                except Exception as e:
                                    app.logger.error(e)

                            Message = f"Task ID {str(dup_id)} duplicated by {session.get('user')}."
                            app.logger.warning(Message)
                            Create_Event(Message)

                    if "," in taskid:

                        for task in taskid.split(","):
                            dup_task(task)

                    else:
                        dup_task(taskid)

                    return redirect(url_for('tasks'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "tasks"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('tasks'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/tasks/return/<tasktype>', methods=['POST'])
        def return_task(tasktype):

            try:

                if session.get('user') and session.get('is_admin'):

                    if tasktype in ["new", "edit"]:

                        if session.get('form_step') == 1:
                            return redirect(url_for('tasks'))

                        elif session.get('form_step') == 2:
                            session['form_step'] = 1

                            if tasktype == "new":
                                return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'), is_admin=session.get('is_admin'), form_step=session.get('form_step'), new_task=True, frequency_field=session.get('task_frequency'), description_field=session.get('task_description'), task_type_field=session.get('form_type'), Valid_Plugins=Valid_Plugins)

                            elif tasktype == "edit":
                                Cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (session.get('task_id'),))
                                result = Cursor.fetchone()
                                return render_template('tasks.html', username=session.get('user'), form_type=session.get('form_type'), is_admin=session.get('is_admin'), form_step=session.get('form_step'), edit_task=True, frequency_field=session.get('task_frequency'), description_field=session.get('task_description'), task_type_field=session.get('form_type'), Valid_Plugins=Valid_Plugins, results=result)

                        else:
                            return redirect(url_for('tasks'))

                    else:
                        return redirect(url_for('tasks'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "tasks"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('tasks'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/task/delete/<taskid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_tasks_delete(taskid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':
                                del_id = int(taskid)
                                Cursor.execute("SELECT frequency FROM tasks WHERE task_id = %s", (del_id,))
                                result = Cursor.fetchone()

                                if result:
                                    Cron_Command = f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(del_id)}'

                                    try:
                                        my_cron = CronTab(user=getpass.getuser())

                                        for job in my_cron:

                                            if job.command == Cron_Command:
                                                my_cron.remove(job)
                                                my_cron.write()

                                    except:
                                        return jsonify({"Error": f"Failed to remove old cronjob. No changes made to task.", "Attempted Cronjob": Cron_Command}), 500

                                Cursor.execute("DELETE FROM tasks WHERE task_id = %s;", (del_id,))
                                Connection.commit()
                                User = Authentication_Verified["Username"]
                                Message = f"Task ID {str(del_id)} deleted by {User}."
                                app.logger.warning(Message)
                                Create_Event(Message)
                                return jsonify({"Message": f"Successfully deleted task id {str(del_id)}."}), 200

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks/delete/<taskid>', methods=['POST'])
        def delete_task(taskid):

            try:

                if session.get('user') and session.get('is_admin'):

                    def del_task(del_id):
                        del_id = int(del_id)
                        Cursor.execute("SELECT frequency FROM tasks WHERE task_id = %s", (del_id,))
                        result = Cursor.fetchone()

                        if result:

                            try:
                                my_cron = CronTab(user=getpass.getuser())

                                for job in my_cron:

                                    if job.command == f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(del_id)}':
                                        my_cron.remove(job)
                                        my_cron.write()

                            except:
                                Cursor.execute("SELECT * FROM tasks")
                                results = Cursor.fetchall()
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'), results=results,
                                                       error=f"Failed to remove task ID {str(del_id)} from crontab.")

                        Cursor.execute("DELETE FROM tasks WHERE task_id = %s;", (del_id,))
                        Connection.commit()
                        Message = f"Task ID {str(del_id)} deleted by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)

                    if "," in taskid:

                        for task in taskid.split(","):
                            del_task(task)

                    else:
                        del_task(taskid)

                    return redirect(url_for('tasks'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "tasks"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('tasks'))

            except Exception as e:
                app.logger.error(e)
                Cursor.execute("SELECT * FROM tasks")
                results = Cursor.fetchall()
                return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                       is_admin=session.get('is_admin'), results=results,
                                       error="Invalid value provided. Failed to delete object.")

        @app.route('/api/task/run/<taskid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_tasks_run(taskid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':
                                Plugin_ID = int(taskid)
                                Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (Plugin_ID,))
                                result = Cursor.fetchone()

                                if result[6] == "Running":
                                    return jsonify({"Error": "Task is already running."}), 500

                                if not Output_API_Checker(result[2]):
                                    jsonify({"Error": f"The task type {result[2]} has not been configured. Please update its configuration in the config.json file."}), 500

                                else:
                                    Plugin_to_Call = plugin_caller.Plugin_Caller(Plugin_Name=result[2], Limit=result[5], Query=result[1], Task_ID=Plugin_ID)
                                    plugin_caller_thread = threading.Thread(target=Plugin_to_Call.Call_Plugin)
                                    plugin_caller_thread.start()
                                    return jsonify({"Message": f"Successfully executed task id {str(Plugin_ID)}."}), 200

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks/run/<taskid>', methods=['POST'])
        def run_task(taskid):

            try:

                if session.get('user') and session.get('is_admin'):
                    Plugin_ID = int(taskid)
                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (Plugin_ID,))
                    result = Cursor.fetchone()

                    if result[6] == "Running":
                        Cursor.execute("SELECT * FROM tasks")
                        task_results = Cursor.fetchall()
                        return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                               is_admin=session.get('is_admin'), results=task_results,
                                               error="Task is already running.")

                    if not Output_API_Checker(result[2]):
                        Cursor.execute("SELECT * FROM tasks")
                        task_results = Cursor.fetchall()
                        return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'),
                                               is_admin=session.get('is_admin'), results=task_results,
                                               api_check="Failed")

                    else:
                        Plugin_to_Call = plugin_caller.Plugin_Caller(Plugin_Name=result[2], Limit=result[5], Query=result[1], Task_ID=Plugin_ID)
                        plugin_caller_thread = threading.Thread(target=Plugin_to_Call.Call_Plugin)
                        plugin_caller_thread.start()
                        return redirect(url_for('tasks'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "tasks"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('tasks'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/task/new', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_tasks_new():

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':

                                if request.is_json:
                                    Content = request.get_json()

                                    if all(Items in Content for Items in ["Task Type", "Query"]):
                                        Frequency = ""
                                        Description = ""
                                        Limit = 0
                                        
                                        if Content['Task Type'] not in Valid_Plugins:
                                            return jsonify({"Error": "The task type is not a valid option."}), 500

                                        if any(char in Content['Query'] for char in Bad_Characters):
                                            return jsonify({"Error": "Potentially dangerous query identified. Please ensure your query does not contain any bad characters."}), 500

                                        if 'Frequency' in Content:
                                            Frequency_Regex = re.search(r"[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}", Content["Frequency"])

                                            if not Frequency_Regex and not Content["Frequency"] == "":
                                                return jsonify({"Error": "The task type is not a valid option."}), 500

                                            else:
                                                Frequency = Content["Frequency"]

                                        if 'Description' in Content:
                                            Description = html.escape(Content['Description'])

                                        if 'Limit' in Content and Content['Task Type'] not in Plugins_without_Limit:
                                            
                                            try:
                                                Limit = int(Content['Limit'])

                                            except:
                                                return jsonify({"Error": "Failed to convert limit to an integer."}), 500

                                        Current_Timestamp = General.Date()  # Variable set as it is needed for two different functions and needs to be consistent.
                                        Cursor.execute('INSERT INTO tasks (query, plugin, description, frequency, task_limit, status, created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)', (
                                        Content["Query"], Content["Task Type"], Description, Frequency, str(Limit), "Stopped", Current_Timestamp, Current_Timestamp,))
                                        Connection.commit()
                                        time.sleep(1)
                                        Cursor.execute("SELECT * FROM tasks WHERE query = %s AND plugin = %s AND description = %s AND frequency = %s AND task_limit = %s AND status = %s AND created_at = %s AND updated_at = %s;", (
                                        Content["Query"], Content["Task Type"], Description, Frequency, str(Limit), "Stopped", str(Current_Timestamp), str(Current_Timestamp),))
                                        result = Cursor.fetchone()
                                        current_task_id = result[0]

                                        if Frequency != "":
                                            Cron_Command = f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(current_task_id)}'

                                            try:
                                                my_cron = CronTab(user=getpass.getuser())
                                                job = my_cron.new(command=Cron_Command)
                                                job.setall(session.get('task_frequency'))
                                                my_cron.write()
                                                Message = f"Task ID {(current_task_id)} created by {session.get('user')}."
                                                app.logger.warning(Message)
                                                Create_Event(Message)

                                            except:
                                                Cursor.execute('UPDATE tasks SET frequency = %s WHERE task_id = %s', ("", current_task_id,))
                                                Connection.commit()
                                                return jsonify({"Error": f"Failed to create cronjob. Task was still created.", "Attempted Cronjob": Cron_Command}), 500

                                        return jsonify({"Message": f"Successfully created task id {str(current_task_id)}"}), 200

                                    else:
                                        return jsonify({"Error": "Missing one or more required fields."}), 500

                                else:
                                    return jsonify({"Error": "Request is not in JSON format."}), 500

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks/new', methods=['POST'])
        def new_task():

            try:

                if session.get('user') and session.get('is_admin'):

                    if session.get('form_step') == 0:
                        session['form_step'] += 1
                        return render_template('tasks.html', username=session.get('user'),
                                               form_type=session.get('form_type'),
                                               is_admin=session.get('is_admin'), form_step=session.get('form_step'),
                                               new_task=True,
                                               Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit)

                    elif session.get('form_step') == 1:

                        if request.form.get('tasktype') and request.form.get('tasktype') not in Valid_Plugins:
                            return render_template('tasks.html', username=session.get('user'),
                                                   form_type=session.get('form_type'),
                                                   new_task=True, Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                   is_admin=session.get('is_admin'),
                                                   form_step=session.get('form_step'),
                                                   error="Invalid task type, please select an option from the provided list for the Task Type field.")

                        if 'frequency' in request.form:
                            session['task_frequency'] = request.form['frequency']
                            task_frequency_regex = re.search(
                                r"[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}",
                                session.get('task_frequency'))

                            if not task_frequency_regex and not session.get('task_frequency') == "":
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_step=session.get('form_step'),
                                                       form_type=session.get('form_type'),
                                                       is_admin=session.get('is_admin'), new_task=True,
                                                       Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                       error="Invalid frequency, please provide a valid frequency in the same way you would set up a cronjob or leave the field blank. i.e. \"* */5 * * *\"")

                        if 'description' in request.form:
                            session['task_description'] = html.escape(request.form['description'])

                        session['form_type'] = request.form['tasktype']                        

                        if 'query' in request.form:

                            if request.form['query']:
                                Frequency_Error = ""
                                session['task_query'] = request.form['query']

                                if request.form.get('limit') and session.get('form_type') not in Plugins_without_Limit:

                                    if any(char in session.get('task_query') for char in Bad_Characters):
                                        return render_template('tasks.html', username=session.get('user'),
                                                                   form_type=session.get('form_type'),
                                                                   form_step=session.get('form_step'), Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                                   is_admin=session.get('is_admin'), new_task=True, error="Invalid query specified, please provide a valid query with no special characters.")

                                    try:
                                        session['task_limit'] = int(request.form['limit'])

                                    except:
                                        return render_template('tasks.html', username=session.get('user'),
                                                               form_type=session.get('form_type'),
                                                               form_step=session.get('form_step'), Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                               is_admin=session.get('is_admin'), new_task=True, error="Invalid limit specified, please provide a valid limit represented by a number.")

                                else:

                                    if any(char in session.get('task_query') for char in Bad_Characters):
                                        return render_template('tasks.html', username=session.get('user'),
                                                                   form_type=session.get('form_type'),
                                                                   form_step=session.get('form_step'), Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                                   is_admin=session.get('is_admin'), new_task=True, error="Invalid query specified, please provide a valid query with no special characters.")

                                Current_Timestamp = General.Date()  # Variable set as it is needed for two different functions and needs to be consistent.
                                Cursor.execute('INSERT INTO tasks (query, plugin, description, frequency, task_limit, status, created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)', (
                                session.get('task_query'), session.get('form_type'), session.get('task_description'),
                                session.get('task_frequency'), session.get('task_limit'), "Stopped",
                                Current_Timestamp, Current_Timestamp,))
                                Connection.commit()
                                time.sleep(1)

                                if session.get('task_frequency'):
                                    Cursor.execute("SELECT * FROM tasks WHERE query = %s AND plugin = %s AND description = %s AND frequency = %s AND task_limit = %s AND status = %s AND created_at = %s AND updated_at = %s;", (
                                    session.get('task_query'), session.get('form_type'), session.get('task_description'),
                                    session.get('task_frequency'), str(session.get('task_limit')),
                                    "Stopped", str(Current_Timestamp), str(Current_Timestamp),))
                                    result = Cursor.fetchone()
                                    current_task_id = result[0]

                                    try:
                                        my_cron = CronTab(user=getpass.getuser())
                                        job = my_cron.new(command=f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(current_task_id)}')
                                        job.setall(session.get('task_frequency'))
                                        my_cron.write()
                                        Message = f"Task ID {(current_task_id)} created by {session.get('user')}."
                                        app.logger.warning(Message)
                                        Create_Event(Message)

                                    except:
                                        Frequency_Error = f"Task created but no cronjob was created due to the supplied frequency being invalid, please double check the frequency for task ID {str(session.get('task_id'))} and use the \"Edit\" button to update it in order for the cronjob to be created."

                                session['form_step'] = 0
                                Cursor.execute("SELECT * FROM tasks")
                                results = Cursor.fetchall()

                                if Frequency_Error:
                                    return render_template('tasks.html', username=session.get('user'),
                                                           form_step=session.get('form_step'), Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                           new_task=True, is_admin=session.get('is_admin'),
                                                           results=results, error=Frequency_Error)

                                return redirect(url_for('tasks'))

                            else:
                                return render_template('tasks.html', username=session.get('user'),
                                                           form_type=session.get('form_type'),
                                                           new_task=True, is_admin=session.get('is_admin'),
                                                           form_step=session.get('form_step'), Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                           error="Empty query, please provide a valid term to search for.")

                        else:
                            return render_template('tasks.html', username=session.get('user'),
                                                       form_type=session.get('form_type'),
                                                       new_task=True, is_admin=session.get('is_admin'),
                                                       form_step=session.get('form_step'), Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                       error="Empty query, please provide a valid term to search for.")
                        
                    else:
                        return redirect(url_for('tasks'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "tasks"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('tasks'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/task/edit/<taskid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_tasks_edit(taskid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':

                                try:
                                    current_task_id = int(taskid)

                                except:
                                    return jsonify({"Error": "Failed to convert task id to an integer."}), 500

                                if request.is_json:
                                    Content = request.get_json()

                                    if all(Items in Content for Items in ["Task Type", "Query"]):
                                        Frequency = ""
                                        Description = ""
                                        Limit = 0
                                        
                                        if Content['Task Type'] not in Valid_Plugins:
                                            return jsonify({"Error": "The task type is not a valid option."}), 500

                                        if any(char in Content['Query'] for char in Bad_Characters):
                                            return jsonify({"Error": "Potentially dangerous query identified. Please ensure your query does not contain any bad characters."}), 500

                                        if 'Frequency' in Content:
                                            Frequency_Regex = re.search(r"[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}\s[\d\/\*\-]{1,6}", Content["Frequency"])

                                            if not Frequency_Regex and Content["Frequency"] != "":
                                                return jsonify({"Error": "The task type is not a valid option."}), 500

                                            else:
                                                Update_Cron = False
                                                Cursor.execute("SELECT frequency FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                                                result = Cursor.fetchone()
                                                Original_Frequency = result[0]
                                                Frequency = Content['Frequency']
                                                Cron_Command = f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {current_task_id}'

                                                if Content['Frequency'] != "" and Content['Frequency'] != Original_Frequency:
                                                    Update_Cron = True

                                                elif Content['Frequency'] != "" and Content['Frequency'] == Original_Frequency:
                                                    Update_Cron = False

                                                elif Content['Frequency'] == "" and Original_Frequency == "":
                                                    Remove_Cron = True

                                                elif Content['Frequency'] != "" and Original_Frequency == "":
                                                    Creat_Cron = True

                                                if Remove_Cron:

                                                    try:
                                                        my_cron = CronTab(user=getpass.getuser())

                                                        for job in my_cron:

                                                            if job.command == Cron_Command:
                                                                my_cron.remove(job)
                                                                my_cron.write()

                                                    except:
                                                        return jsonify({"Error": f"Failed to create cronjob. No changes made to task.", "Attempted Cronjob": Cron_Command}), 500

                                                if Update_Cron:
                                                    my_cron = CronTab(user=getpass.getuser())

                                                    try:

                                                        for job in my_cron:

                                                            if job.command == Cron_Command:
                                                                my_cron.remove(job)
                                                                my_cron.write()

                                                    except:
                                                        return jsonify({"Error": f"Failed to remove old cronjob. No changes made to task.", "Attempted Cronjob": Cron_Command}), 500

                                                    try:
                                                        job = my_cron.new(command=Cron_Command)
                                                        job.setall(Frequency)
                                                        my_cron.write()

                                                    except:
                                                        return jsonify({"Error": f"Failed to create new cronjob. No changes made to task.", "Attempted Cronjob": Cron_Command}), 500

                                                if Create_Cron:

                                                    try:
                                                        job = my_cron.new(command=Cron_Command)
                                                        job.setall(Frequency)
                                                        my_cron.write()

                                                    except:
                                                        return jsonify({"Error": f"Failed to create new cronjob. No changes made to task.", "Attempted Cronjob": Cron_Command}), 500
                                                

                                        if 'Description' in Content:
                                            Description = html.escape(Content['Description'])

                                        if 'Limit' in Content and Content['Task Type'] not in Plugins_without_Limit:
                                            
                                            try:
                                                Limit = int(Content['Limit'])

                                            except:
                                                return jsonify({"Error": "Failed to convert limit to an integer."}), 500

                                        Current_Timestamp = General.Date()  # Variable set as it is needed for two different functions and needs to be consistent.
                                        Cursor.execute('UPDATE tasks SET query = %s, plugin = %s, description = %s, frequency = %s, task_limit = %s, updated_at = %s WHERE task_id = %s', (Content["Query"], Content["Task Type"], Description, Frequency, str(Limit), Current_Timestamp, current_task_id,))
                                        Connection.commit()
                                        return jsonify({"Message": f"Successfully updated task id {str(current_task_id)}"}), 200

                                    else:
                                        return jsonify({"Error": "Missing one or more required fields."}), 500

                                else:
                                    return jsonify({"Error": "Request is not in JSON format."}), 500

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks/edit/<taskid>', methods=['POST'])
        def edit_task(taskid):

            try:

                if session.get('user') and session.get('is_admin'):

                    if session.get('form_step') == 0:

                        session['task_id'] = int(taskid)
                        Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                        results = Cursor.fetchone()

                        if results:
                            session['form_step'] += 1
                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), edit_task=True, Valid_Plugins=Valid_Plugins, is_admin=session.get('is_admin'), results=results, Plugins_without_Limit=Plugins_without_Limit, Without_Limit=(results[2] in Plugins_without_Limit))

                        else:
                            Cursor.execute("SELECT * FROM tasks;", (session.get('task_id'),))
                            results = Cursor.fetchall()
                            return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit, results=results, is_admin=session.get('is_admin'), error="Invalid value provided. Failed to edit object.")

                    elif session.get('form_step') == 1:
                        Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                        results = Cursor.fetchone()

                        if request.form.get('tasktype') and request.form.get('tasktype') in Valid_Plugins:

                            if 'frequency' in request.form:
                                session['task_frequency'] = request.form['frequency']
                                task_frequency_regex = re.search(r"[\d\/\*\-\,]+\s[\d\/\*\-\,]+\s[\d\/\*\-\,]+\s[\d\/\*\-\,]+\s[\d\/\*\-\,]+", session.get('task_frequency'))

                                if not task_frequency_regex and not session.get('task_frequency') == "":
                                    return render_template('tasks.html', username=session.get('user'), form_step=session.get('form_step'), edit_task=True, Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit, results=results, is_admin=session.get('is_admin'), error="Invalid frequency, please provide a valid frequency in the same way you would set up a cronjob or leave the field blank. i.e. \"* /5 * * *\"")

                            if 'description' in request.form:
                                session['task_description'] = html.escape(request.form['description'])

                            session['form_type'] = request.form['tasktype']

                        else:
                            return render_template('tasks.html', username=session.get('user'),
                                                   form_step=session.get('form_step'),
                                                   edit_task=True, Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                   is_admin=session.get('is_admin'), results=results,
                                                   error="Invalid task type, please select an option from the provided list for the Task Type field.")

                        if 'query' in request.form:

                            if request.form['query']:
                                Frequency_Error = ""
                                session['task_query'] = request.form['query']

                                if request.form.get('limit') and session.get('form_type') not in Plugins_without_Limit:

                                    if any(char in session.get('task_query') for char in Bad_Characters):
                                        return render_template('tasks.html', username=session.get('user'),
                                                                   form_step=session.get('form_step'), edit_task=True, Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                                   results=results, is_admin=session.get('is_admin'),
                                                                   form_type=session.get('form_type'),
                                                                   error="Invalid query specified, please provide a valid query with no special characters.")

                                    try:
                                        session['task_limit'] = int(request.form['limit'])

                                    except:
                                        return render_template('tasks.html', username=session.get('user'),
                                                               form_step=session.get('form_step'), edit_task=True,
                                                               form_type=session.get('form_type'),
                                                               Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit, results=results,
                                                               is_admin=session.get('is_admin'),
                                                               error="Invalid limit specified, please provide a valid limit represented by a number.")

                                else:

                                    if session["form_type"] == "Domain Fuzzer - Punycode (Latin Condensed)" and len(session['task_query']) > 15:
                                        return render_template('tasks.html', username=session.get('user'),
                                                               form_step=session.get('form_step'), edit_task=True,
                                                               form_type=session.get('form_type'),
                                                               Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit, results=results,
                                                               is_admin=session.get('is_admin'),
                                                               error="For the task Domain Fuzzer - Punycode (Latin Condensed), the length of the query cannot be longer than 15 characters.")

                                    elif session["form_type"] in ["Domain Fuzzer - Punycode (Latin Comprehensive)", "Domain Fuzzer - Punycode (Middle Eastern)", "Domain Fuzzer - Punycode (Asian)", "Domain Fuzzer - Punycode (Native American)", "Domain Fuzzer - Punycode (North African)"] and len(session['task_query']) > 10:
                                        sess_form_type = session["form_type"]
                                        return render_template('tasks.html', username=session.get('user'),
                                                               form_step=session.get('form_step'), edit_task=True,
                                                               form_type=session.get('form_type'),
                                                               Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit, results=results,
                                                               is_admin=session.get('is_admin'),
                                                               error=f"For the task {sess_form_type}, the length of the query cannot be longer than 10 characters.")

                                    if any(char in session.get('task_query') for char in Bad_Characters):
                                        return render_template('tasks.html', username=session.get('user'),
                                                                   form_type=session.get('form_type'),
                                                                   form_step=session.get('form_step'), edit_task=True,
                                                                   is_admin=session.get('is_admin'),
                                                                   Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit, results=results,
                                                                   error="Invalid query specified, please provide a valid query with no special characters.")

                                Update_Cron = False

                                if session.get('task_frequency') != "":
                                    Cursor.execute("SELECT frequency FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                                    result = Cursor.fetchone()
                                    original_frequency = result[0]

                                    if not original_frequency == session.get('task_frequency'):
                                        Update_Cron = True

                                else:

                                    if results[4] != "":

                                        try:
                                            my_cron = CronTab(user=getpass.getuser())

                                            for job in my_cron:

                                                if job.command == f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(session.get("task_id"))}':
                                                    my_cron.remove(job)
                                                    my_cron.write()

                                        except:
                                            return render_template('tasks.html', username=session.get('user'),
                                                                   form_type=session.get('form_type'),
                                                                   form_step=session.get('form_step'), Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                                   is_admin=session.get('is_admin'), edit_task=True,
                                                                   error="Failed to update cron job.")

                                Cursor.execute('UPDATE tasks SET query = %s, plugin = %s, description = %s, frequency = %s, task_limit = %s, updated_at = %s WHERE task_id = %s', (
                                session.get('task_query'), session.get('form_type'), session.get('task_description'),
                                session.get('task_frequency'), session.get('task_limit'), General.Date(),
                                session.get('task_id'),))
                                Connection.commit()
                                time.sleep(1)

                                if Update_Cron:
                                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                                    result = Cursor.fetchone()
                                    current_task_id = result[0]

                                    try:
                                        my_cron = CronTab(user=getpass.getuser())

                                        for job in my_cron:

                                            if job.command == f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(current_task_id)}':
                                                my_cron.remove(job)
                                                my_cron.write()

                                        job = my_cron.new(command=f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(current_task_id)}')
                                        job.setall(session.get('task_frequency'))
                                        my_cron.write()

                                    except:
                                        Frequency_Error = f"Task updated but no cronjob was added, and any valid original cron jobs for this task have been removed due to an invalid frequency being supplied, please double check the frequency for task ID {str(session.get('task_id'))} and use the \"Edit\" button to edit the frequency to create a cronjob."

                                Message = f"Task ID {str(session.get('task_id'))} updated by {session.get('user')}."
                                app.logger.warning(Message)
                                Create_Event(Message)
                                session['form_step'] = 0
                                Cursor.execute("SELECT * FROM tasks")
                                results = Cursor.fetchall()

                                if Frequency_Error:
                                    return render_template('tasks.html', username=session.get('user'),
                                                           form_step=session.get('form_step'), Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit,
                                                           new_task=True, is_admin=session.get('is_admin'),
                                                           results=results, error=Frequency_Error)

                                return redirect(url_for('tasks'))

                            else:
                                return render_template('tasks.html', username=session.get('user'),
                                                           form_step=session.get('form_step'), new_task=True,
                                                           Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit, is_admin=session.get('is_admin'),
                                                           results=results,
                                                           error="Empty query, please provide a valid term to search for.")

                        else:
                            return render_template('tasks.html', username=session.get('user'),
                                                       form_step=session.get('form_step'), new_task=True,
                                                       Valid_Plugins=Valid_Plugins, Plugins_without_Limit=Plugins_without_Limit, is_admin=session.get('is_admin'),
                                                       results=results,
                                                       error="Empty query, please provide a valid term to search for.")

                    else:
                        return redirect(url_for('tasks'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "tasks"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('tasks'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/tasks')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_task_details():

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified.get("Token"):

                        if request.method == 'GET':

                            if request.is_json:
                                Content = request.get_json()
                                data = {}
                                Safe_Content = {}

                                for Item in ["ID", "Query", "Plugin", "Description", "Frequency", "Limit", "Status", "Created At", "Updated At"]:

                                    if Item in Content:

                                        if any(char in Item for char in Bad_Characters):
                                            return jsonify({"Error": f"Bad characters detected in the {Item} field."}), 500

                                        if Item == "ID":

                                            if type(Content[Item]) != int:
                                                return jsonify({"Error": f"The ID provided is not an integer."}), 500

                                            Safe_Content["task_id"] = Content[Item]

                                        elif Item == "Limit":
                                            Safe_Content["task_limit"] = Content[Item]

                                        elif Item == "Created At":
                                            Safe_Content["created_at"] = Content[Item]

                                        elif Item == "Updated At":
                                            Safe_Content["updated_at"] = Content[Item]

                                        else:
                                            Safe_Content[Item.lower()] = Content[Item]

                                if len(Safe_Content) > 1:
                                    Select_Query = "SELECT * FROM tasks WHERE "

                                    for Item_Key, Item_Value in sorted(Safe_Content.items()):
                                        Select_Query += f"{Item_Key} = '{Item_Value}'"

                                        if Item_Key != sorted(Safe_Content.keys())[-1]:
                                            Select_Query += " and "

                                        else:
                                            Select_Query += ";"

                                    Cursor.execute(Select_Query)

                                elif len(Safe_Content) == 1:
                                    Key = list(Safe_Content.keys())[0]
                                    Val = list(Safe_Content.values())[0]
                                    Cursor.execute(f"SELECT * FROM tasks WHERE {Key} = '{Val}';")

                                else:
                                    return jsonify({"Error": "No valid fields found in request."}), 500

                                for Task in Cursor.fetchall():
                                    data[Task[0]] = {"Query": Task[1], "Plugin": Task[2], "Description": Task[3], "Frequency": Task[4], "Limit": int(Task[5]), "Status": Task[6], "Created Timestamp": Task[7], "Last Updated Timestamp": Task[8]}

                                return jsonify(data), 200

                            else:
                                data = {}
                                Cursor.execute('SELECT * FROM tasks ORDER BY task_id DESC LIMIT 1000')

                                for Task in Cursor.fetchall():
                                    data[Task[0]] = {"Query": Task[1], "Plugin": Task[2], "Description": Task[3], "Frequency": Task[4], "Limit": int(Task[5]), "Status": Task[6], "Created Timestamp": Task[7], "Last Updated Timestamp": Task[8]}

                                return jsonify(data), 200

                        else:
                            return jsonify({"Error": "Method not allowed."}), 500

                    else:

                        if Authentication_Verified.get("Message"):
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown Exception Occurred."}), 500

        @app.route('/results/new', methods=['POST'])
        def new_result():

            try:

                if session.get('user') and session.get('is_admin'):

                    if session.get('form_step') == 0:
                        session['form_step'] += 1
                        return render_template('results.html', username=session.get('user'),
                                               form_step=session.get('form_step'),
                                               is_admin=session.get('is_admin'), Finding_Types=Finding_Types)

                    elif session.get('form_step') == 1:
                        name = request.form['name']
                        URL = request.form['url']
                        Type = request.form['type']

                        if name and URL and Type:

                            if any(char in name for char in Bad_Characters):
                                return render_template('results.html', username=session.get('user'),
                                                           form_step=session.get('form_step'),
                                                           is_admin=session.get('is_admin'), Finding_Types=Finding_Types,
                                                           error="Bad characters identified in the name field, please remove special characters from the name field.")

                            if not Type in Finding_Types:
                                return render_template('results.html', username=session.get('user'),
                                                       form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'), Finding_Types=Finding_Types,
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
                                    return render_template('results.html', username=session.get('user'),
                                                           form_step=session.get('form_step'),
                                                           is_admin=session.get('is_admin'), Finding_Types=Finding_Types,
                                                           error="Invalid URL(s).")

                            for Iterator in Iterator_List:
                                URL_Regex = re.search(
                                    r"https?:\/\/(www\.)?([a-z\.]+\.\w{2,3}(\.\w{2,3})?(\.\w{2,3})?)",
                                    Hosts_List[Iterator])

                                try:
                                    Cursor.execute('INSERT INTO results (task_id, title, status, plugin, domain, link, created_at, updated_at, result_type) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)', (
                                    0, str(Query_List[Iterator]), "Open", "Manual Entry", str(URL_Regex.group(2)),
                                    str(Hosts_List[Iterator]), General.Date(), General.Date(), Type,))
                                    Connection.commit()

                                except Exception as e:
                                    app.logger.error(e)

                            return redirect(url_for('results'))

                        else:
                            return render_template('results.html', username=session.get('user'),
                                                   form_step=session.get('form_step'),
                                                   is_admin=session.get('is_admin'), Finding_Types=Finding_Types,
                                                   error="Invalid entry / entries, please fill out all necessary fields.")

                    else:
                        return redirect(url_for('results'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "results"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('results'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/api/result/new', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_results_new():

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':

                                if request.is_json:
                                    Content = request.get_json()

                                    if all(Items in Content for Items in ["Name", "URL", "Type"]):
                                        Name = Content['Name']
                                        URL = Content['URL']
                                        Type = Content['Type']

                                        if any(char in Name for char in Bad_Characters):
                                            return jsonify({"Error": "Bad characters identified in the name field, please remove special characters."}), 500

                                        if not Type in Finding_Types:
                                            Joint_Finding_Types = ", ".join(Finding_Types)
                                            return jsonify({"Error": f"Result type is not valid. Please use one of the following result types {Joint_Finding_Types}"}), 500

                                        if type(Name) == list:
                                            Query_List = Name

                                        else:
                                            Query_List = General.Convert_to_List(Name)

                                        if type(URL) == list:
                                            Hosts_List = URL

                                        else:
                                            Hosts_List = General.Convert_to_List(URL)

                                        if len(Query_List) != len(Hosts_List):
                                            return jsonify({"Error": "Please provide the same amount of result names as result URLs."}), 500

                                        Iterator_List = []
                                        i = 0

                                        while i < len(Hosts_List) and len(Query_List):
                                            URL_Regex = re.search(r"https?:\/\/(www\.)?([a-z0-9\.]+\.\w{2,3}(\.\w{2,3})?(\.\w{2,3})?)", Hosts_List[i])

                                            if URL_Regex:
                                                Iterator_List.append(i)
                                                i += 1

                                            else:
                                                return jsonify({"Error": "Information supplied to the URL field could not be identified as a URL / URLs."}), 500

                                        for Iterator in Iterator_List:
                                            URL_Regex = re.search(r"https?:\/\/(www\.)?([a-z0-9\.]+\.\w{2,3}(\.\w{2,3})?(\.\w{2,3})?)", Hosts_List[Iterator])

                                            try:
                                                Cursor.execute('INSERT INTO results (task_id, title, status, plugin, domain, link, created_at, updated_at, result_type) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)', (
                                                0, str(Query_List[Iterator]), "Open", "Manual Entry", str(URL_Regex.group(2)), str(Hosts_List[Iterator]), General.Date(), General.Date(), Type,))
                                                Connection.commit()

                                            except Exception as e:
                                                app.logger.error(e)

                                        if len(Query_List) > 1:
                                            return jsonify({"Message": "Successfully created results."}), 200

                                        else:
                                            return jsonify({"Message": "Successfully created result."}), 200

                                    else:
                                        return jsonify({"Error": "One or more fields has not been provided."}), 500

                                else:
                                    return jsonify({"Error": "Request is not in JSON format."}), 500

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/results/delete/<resultid>', methods=['POST'])
        def delete_result(resultid):

            try:

                if session.get('user') and session.get('is_admin'):

                    def del_result(resultid):
                        result_id = int(resultid)
                        Cursor.execute("SELECT * FROM results WHERE result_id = %s", (result_id,))
                        Result = Cursor.fetchone()

                        if Result[9]:
                            Screenshot_File = f"{File_Path}/static/protected/screenshots/{Result[9]}"

                            if os.path.exists(Screenshot_File):
                                os.remove(Screenshot_File)

                        if Result[10]:
                            Output_File = f"{File_Path}/{Result[10]}"

                            if os.path.exists(Output_File):
                                os.remove(Output_File)

                        Cursor.execute("DELETE FROM results WHERE result_id = %s;", (result_id,))
                        Connection.commit()
                        Message = f"Result ID {str(result_id)} deleted by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)

                    if "," in resultid:

                        for resid in resultid.split(","):
                            del_result(resid)

                    else:
                        del_result(resultid)

                    return redirect(url_for('results'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "results"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('results'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/api/result/delete/<resultid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_results_delete(resultid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':
                                result_id = int(resultid)
                                Cursor.execute("SELECT * FROM results WHERE result_id = %s", (result_id,))
                                Result = Cursor.fetchone()

                                if not Result:
                                    return jsonify({"Error": f"Unable to find result id {str(result_id)}."}), 500

                                if Result[9]:
                                    Screenshot_File = f"{File_Path}/static/protected/screenshots/{Result[9]}"

                                    if os.path.exists(Screenshot_File):
                                        os.remove(Screenshot_File)

                                if Result[10]:
                                    Output_File = f"{File_Path}/{Result[10]}"

                                    if os.path.exists(Output_File):
                                        os.remove(Output_File)

                                Cursor.execute("DELETE FROM results WHERE result_id = %s;", (result_id,))
                                Connection.commit()
                                User = Authentication_Verified["Username"]
                                Message = f"Result ID {str(result_id)} deleted by {User}."
                                app.logger.warning(Message)
                                Create_Event(Message)
                                return jsonify({"Message": "Successfully deleted result."}), 500

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/results/changestatus/<status>/<resultid>', methods=['POST'])
        def change_result_status(status, resultid):

            try:

                if session.get('user') and session.get('is_admin'):

                    if status in ["open", "close", "inspect", "review"]:

                        def change_status_inner(resultid):

                            if status == "open":
                                Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Open", str(General.Date()), resultid,))
                                Message = f"Result ID {str(resultid)} re-opened by {session.get('user')}."

                            elif status == "close":
                                Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Closed", str(General.Date()), resultid,))
                                Message = f"Result ID {str(resultid)} closed by {session.get('user')}."

                            elif status == "inspect":
                                Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Inspecting", str(General.Date()), resultid,))
                                Message = f"Result ID {str(resultid)} now under inspection by {session.get('user')}."

                            elif status == "review":
                                Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Reviewing", str(General.Date()), resultid,))
                                Message = f"Result ID {str(resultid)} now under review by {session.get('user')}."

                            Connection.commit()
                            app.logger.warning(Message)
                            Create_Event(Message)

                        if "," in resultid:

                            for resid in resultid.split(","):
                                change_status_inner(int(resid))

                        else:
                            change_status_inner(resultid)

                        return redirect(url_for('results'))

                    else:
                        return redirect(url_for('results'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "results"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('results'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/api/result/changestatus/<status>/<resultid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_results_changestatus(status, resultid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':
                                result_id = int(resultid)
                                User = Authentication_Verified["Username"]

                                if status == "open":
                                    Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Open", str(General.Date()), resultid,))
                                    Message = f"Result ID {str(resultid)} re-opened by {User}."

                                elif status == "close":
                                    Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Closed", str(General.Date()), resultid,))
                                    Message = f"Result ID {str(resultid)} closed by {User}."

                                elif status == "inspect":
                                    Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Inspecting", str(General.Date()), resultid,))
                                    Message = f"Result ID {str(resultid)} now under inspection by {User}."

                                elif status == "review":
                                    Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Reviewing", str(General.Date()), resultid,))
                                    Message = f"Result ID {str(resultid)} now under review by {User}."

                                Connection.commit()
                                app.logger.warning(Message)
                                Create_Event(Message)
                                return jsonify({"Message": f"Successfully changed the status for result ID {resultid}."}), 500

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/results/details/<resultid>', methods=['GET'])
        def result_details(resultid):

            try:

                if session.get('user'):
                    resultid = int(resultid)
                    Cursor.execute("SELECT * FROM results WHERE result_id = %s", (resultid,))
                    Result_Table_Results = Cursor.fetchone()
                    Output_Files = Result_Table_Results[10].split(", ")
                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (Result_Table_Results[1],))
                    Task_Table_Results = Cursor.fetchone()
                    return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'), details=True, is_admin=session.get('is_admin'), results=Result_Table_Results, task_results=Task_Table_Results, Output_Files=Output_Files, Screenshot_Permitted=Permit_Screenshots)

                else:
                    session["next_page"] = "results"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/results/filtered', methods=['GET', 'POST'])
        def results_filtered():

            try:
            
                if session.get('user'):
                    session['form_step'] = 0
                
                    if 'filter' in request.args and 'filtervalue' in request.args:
                        Filter = str(request.args['filter'])
                        Filter_Value = str(request.args['filtervalue'])

                        if "ID" in Filter:
                            Filter_Value = int(Filter_Value)

                        if Filter in Result_Filters:
                            Converted_Filter = Filter.lower().replace(" ", "_")
                        
                            if type(Filter_Value) == int:
                                Cursor.execute(f"SELECT * FROM results WHERE {Converted_Filter} = {Filter_Value} ORDER BY result_id DESC LIMIT 1000")

                            elif (type(Filter_Value) == str and not any(char in Filter_Value for char in Bad_Characters)):
                                Cursor.execute(f"SELECT * FROM results WHERE {Converted_Filter} = \'{Filter_Value}\' ORDER BY result_id DESC LIMIT 1000")
                            
                            else:
                                return redirect(url_for('results'))

                            return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), Filter_Name=Filter, Filter_Value=Filter_Value, Finding_Types=Finding_Types, Result_Filters=Result_Filters)

                        else:
                            return redirect(url_for('results'))

                    else:
                        return redirect(url_for('results'))

                else:
                    session["next_page"] = "results_filtered"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/results', methods=['GET'])
        def results():

            try:

                if session.get('user'):
                    session['form_step'] = 0
                    Cursor.execute("SELECT * FROM results ORDER BY result_id DESC LIMIT 1000")
                    return render_template('results.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), Result_Filters=Result_Filters)

                else:
                    session["next_page"] = "results"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/api/results')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_results_all():

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified.get("Token"):

                        if request.method == 'GET':

                            if request.is_json:
                                Content = request.get_json()
                                data = {}
                                Safe_Content = {}

                                for Item in ["ID", "Associated Task ID", "Title", "Plugin", "Domain", "Link", "Screenshot URL", "Status", "Created At", "Updated At", "Output Files", "Result Type", "Screenshot Requested"]:

                                    if Item in Content:

                                        if any(char in Item for char in Bad_Characters):
                                            return jsonify({"Error": f"Bad characters detected in the {Item} field."}), 500

                                        if Item == "ID":

                                            if type(Content[Item]) != int:
                                                return jsonify({"Error": f"The ID provided is not an integer."}), 500

                                            Safe_Content["result_id"] = Content[Item]

                                        elif Item == "Associated Task ID":
                                            Safe_Content["task_id"] = Content[Item]

                                        elif " " in Item:
                                            Safe_Content[Item.lower().replace(" ", "_")] = Content[Item]

                                        else:
                                            Safe_Content[Item.lower()] = Content[Item]

                                if len(Safe_Content) > 1:
                                    Select_Query = "SELECT * FROM results WHERE "

                                    for Item_Key, Item_Value in sorted(Safe_Content.items()):
                                        Select_Query += f"{Item_Key} = '{Item_Value}'"

                                        if Item_Key != sorted(Safe_Content.keys())[-1]:
                                            Select_Query += " and "

                                        else:
                                            Select_Query += ";"

                                    Cursor.execute(Select_Query)

                                elif len(Safe_Content) == 1:
                                    Key = list(Safe_Content.keys())[0]
                                    Val = list(Safe_Content.values())[0]
                                    Cursor.execute(f"SELECT * FROM results WHERE {Key} = '{Val}';")

                                else:
                                    return jsonify({"Error": "No valid fields found in request."}), 500

                                for Result in Cursor.fetchall():
                                    data[Result[0]] = {"Associated Task ID": Result[1], "Title": Result[2], "Plugin": Result[3], "Status": Result[4], "Domain": Result[5], "Link": Result[6], "Created Timestamp": Result[7], "Last Updated Timestamp": Result[8], "Screenshot Location": Result[9], "Output File Location": Result[10], "Result Type": Result[11], "Screenshot Requested": Result[12]}

                                return jsonify(data), 200

                            else:
                                data = {}
                                Cursor.execute('SELECT * FROM results ORDER BY result_id DESC LIMIT 1000')

                                for Result in Cursor.fetchall():
                                    data[Result[0]] = {"Associated Task ID": Result[1], "Title": Result[2], "Plugin": Result[3], "Status": Result[4], "Domain": Result[5], "Link": Result[6], "Created Timestamp": Result[7], "Last Updated Timestamp": Result[8], "Screenshot Location": Result[9], "Output File Location": Result[10], "Result Type": Result[11], "Screenshot Requested": Result[12]}

                                return jsonify(data), 200

                        else:
                            return jsonify({"Error": "Method not allowed."}), 500

                    else:

                        if Authentication_Verified.get("Message"):
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except:
                return jsonify({"Error": "Unknown Exception Occurred."}), 500

        def check_security_requirements(Password):

            try:

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

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('dashboard'))

        @app.route('/api/account/new', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_accounts_new():

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':

                                if request.is_json:
                                    Content = request.get_json()

                                    if all(Items in Content for Items in ["Username", "Password", "Password Retype", "Administrator"]):

                                        if not Content['Username']:
                                            return jsonify({"Error": "Please provide a valid username."}), 500

                                        if any(char in Content['Username'] for char in Bad_Characters):
                                            return jsonify({"Error": "Bad character detected in username."}), 500

                                        Cursor.execute('SELECT * FROM users WHERE username = %s', (request.form.get('Username'),))
                                        User = Cursor.fetchone()

                                        if User:
                                            return jsonify({"Error": "Username already exists."}), 500

                                        if Content['Password'] != Content['Password Retype']:
                                            return jsonify({"Error": "Please make sure the \"Password\" and \"Retype Password\" fields match."}), 500

                                        else:

                                            if not check_security_requirements(Content['Password']):
                                                return jsonify({"Error": "The supplied password does not meet security complexity requirements."}), 500

                                            else:
                                                Password = generate_password_hash(Content['Password'])
                                                User = Authentication_Verified["Username"]

                                                if Content["Administrator"]:
                                                    Cursor.execute('INSERT INTO users (username, password, blocked, is_admin) VALUES (%s,%s,%s,%s)',(Content['Username'], Password, "False", "True",))
                                                    Message = f"New administrative user {Content['Username']} created by {User}."

                                                else:
                                                    Cursor.execute('INSERT INTO users (username, password, blocked, is_admin) VALUES (%s,%s,%s,%s)',(Content['Username'], Password, "False", "False",))
                                                    Message = f"New low-privileged user {Content['Username']} created by {User}."

                                                Connection.commit()
                                                Create_Event(Message)
                                                return jsonify({"Message": f"Successfully created user {Content['Username']}."}), 200

                                    else:
                                        return jsonify({"Error": "One or more fields has not been provided."}), 500

                                else:
                                    return jsonify({"Error": "Request is not in JSON format."}), 500

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/account/new', methods=['POST'])
        def new_account():

            try:

                if session.get('user') and session.get('is_admin'):

                    if session.get('form_step') == 0:
                        session['form_step'] += 1
                        session['form_type'] = "CreateUser"
                        return render_template('account.html', username=session.get('user'),
                                               form_type=session.get('form_type'), form_step=session.get('form_step'),
                                               is_admin=session.get('is_admin'), api_key=session.get('api_key'),
                                               current_user_id=session.get('user_id'))

                    elif session.get('form_step') == 1:

                        if not request.form['Username']:
                            return render_template('account.html', username=session.get('user'),
                                                   form_type=session.get('form_type'), form_step=session.get('form_step'),
                                                   is_admin=session.get('is_admin'), results=Cursor.fetchall(),
                                                   error="Please provide a valid username.", api_key=session.get('api_key'),
                                                   current_user_id=session.get('user_id'))

                        if any(char in request.form['Username'] for char in Bad_Characters):
                            return render_template('account.html', username=session.get('user'),
                                                       form_type=session.get('form_type'),
                                                       form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                       results=Cursor.fetchall(),
                                                       error="Bad character detected in username.",
                                                       api_key=session.get('api_key'),
                                                       current_user_id=session.get('user_id'))

                        Cursor.execute('SELECT * FROM users WHERE username = %s', (request.form.get('Username'),))
                        User = Cursor.fetchone()

                        if User:
                            Cursor.execute('SELECT * FROM users')
                            return render_template('account.html', username=session.get('user'),
                                                   form_type=session.get('form_type'), form_step=session.get('form_step'),
                                                   is_admin=session.get('is_admin'), results=Cursor.fetchall(),
                                                   error="Username already exists.", api_key=session.get('api_key'),
                                                   current_user_id=session.get('user_id'))

                        Cursor.execute('SELECT * FROM users')

                        if request.form['New_Password'] != request.form['New_Password_Retype']:
                            return render_template('account.html', username=session.get('user'),
                                                   form_type=session.get('form_type'), form_step=session.get('form_step'),
                                                   is_admin=session.get('is_admin'), results=Cursor.fetchall(),
                                                   error="Please make sure the \"New Password\" and \"Retype Password\" fields match.",
                                                   api_key=session.get('api_key'), current_user_id=session.get('user_id'))

                        else:

                            if not check_security_requirements(request.form['New_Password']):
                                return render_template('account.html', username=session.get('user'),
                                                       form_type=session.get('form_type'),
                                                       form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                       results=Cursor.fetchall(), requirement_error=[
                                        "The supplied password does not meet security requirements. Please make sure the following is met:",
                                        "- The password is longer that 8 characters.",
                                        "- The password contains 1 or more UPPERCASE and 1 or more lowercase character.",
                                        "- The password contains 1 or more number.",
                                        "- The password contains one or more special character. Ex. @."],
                                                       api_key=session.get('api_key'),
                                                       current_user_id=session.get('user_id'))

                            else:
                                Password = generate_password_hash(request.form['New_Password'])

                                if 'is_new_user_admin' in request.form:
                                    Cursor.execute('INSERT INTO users (username, password, blocked, is_admin) VALUES (%s,%s,%s,%s)', (request.form['Username'], Password, "False", "True",))
                                    Message = f"New administrative user created by {session.get('user')}."

                                else:
                                    Cursor.execute('INSERT INTO users (username, password, blocked, is_admin) VALUES (%s,%s,%s,%s)', (request.form['Username'], Password, "False", "False",))
                                    Message = f"New low-privileged user created by {session.get('user')}."

                                Connection.commit()
                                Create_Event(Message)
                                return render_template('account.html', username=session.get('user'),
                                                       form_type=session.get('form_type'),
                                                       form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                       results=Cursor.fetchall(), message=Message,
                                                       api_key=session.get('api_key'),
                                                       current_user_id=session.get('user_id'))

                    else:
                        return redirect(url_for('account'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "account"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/account/password/change/<accountid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_accounts_password_change(accountid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':

                                if request.is_json:
                                    Content = request.get_json()

                                    if all(Items in Content for Items in ["Password", "Password Retype"]):

                                        try:
                                            accountid = int(accountid)

                                        except:
                                            return jsonify({"Error": "Could not convert the provided account ID to an integer."}), 500

                                        Cursor.execute('SELECT * FROM users WHERE user_id = %s', (accountid,))
                                        User = Cursor.fetchone()

                                        if User:

                                            if Content['Password'] != Content['Password Retype']:
                                                return jsonify({"Error": "Please make sure the \"Password\" and \"Retype Password\" fields match."}), 500

                                            else:

                                                if not check_password_hash(User[2], Content['Password']):

                                                    if not check_security_requirements(Content['Password']):
                                                        return jsonify({"Error": "The supplied password does not meet security complexity requirements."}), 500

                                                    else:
                                                        Password = generate_password_hash(Content['Password'])
                                                        Cursor.execute('UPDATE users SET password = %s WHERE user_id = %s', (Password, accountid,))
                                                        Connection.commit()
                                                        return jsonify({"Message": f"Successfully changed password for user {User[1]}."}), 200

                                                else:
                                                    return jsonify({"Message": "Your current password and new password cannot be the same."}), 200

                                        else:
                                            return jsonify({"Error": f"Could not find any users with the account ID {str(accountid)}"}), 500

                                    else:
                                        return jsonify({"Error": "One or more fields has not been provided."}), 500

                                else:
                                    return jsonify({"Error": "Request is not in JSON format."}), 500

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/account/password/change/<account>', methods=['POST'])
        def change_account_password(account):

            try:

                if session.get('user'):

                    if str(account) == "mine" and 'Current_Password' in request.form and 'New_Password' in request.form and 'New_Password_Retype' in request.form:
                        Current_Password = request.form['Current_Password']
                        Cursor.execute('SELECT * FROM users WHERE username = %s', (session.get('user'),))
                        User = Cursor.fetchone()

                        if not check_password_hash(User[2], Current_Password):
                            return render_template('account.html', username=session.get('user'),
                                                   form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                   error="Current Password is incorrect.", api_key=session.get('api_key'),
                                                   current_user_id=account)

                        else:

                            if request.form['New_Password'] != request.form['New_Password_Retype']:
                                return render_template('account.html', username=session.get('user'),
                                                       form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                       error="Please make sure the \"New Password\" and \"Retype Password\" fields match.",
                                                       api_key=session.get('api_key'),
                                                       current_user_id=account)

                            else:

                                if not check_password_hash(User[2], request.form['New_Password']):

                                    if not check_security_requirements(request.form['New_Password']):
                                        return render_template('account.html', username=session.get('user'),
                                                               form_step=session.get('form_step'),
                                                               is_admin=session.get('is_admin'), requirement_error=[
                                                "The supplied password does not meet security requirements. Please make sure the following is met:",
                                                "- The password is longer that 8 characters.",
                                                "- The password contains 1 or more UPPERCASE and 1 or more lowercase character.",
                                                "- The password contains 1 or more number.",
                                                "- The password contains one or more special character. Ex. @."],
                                                               api_key=session.get('api_key'),
                                                               current_user_id=account)

                                    else:
                                        password = generate_password_hash(request.form['New_Password'])
                                        Cursor.execute('UPDATE users SET password = %s WHERE user_id = %s', (password, User[0],))
                                        Connection.commit()
                                        return render_template('account.html', username=session.get('user'),
                                                               form_step=session.get('form_step'),
                                                               is_admin=session.get('is_admin'), message="Password changed.",
                                                               api_key=session.get('api_key'),
                                                               current_user_id=account)

                                else:
                                    return render_template('account.html', username=session.get('user'),
                                                       form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                       error="Your current password and new password cannot be the same.",
                                                       api_key=session.get('api_key'),
                                                       current_user_id=account)

                    else:

                        if session.get('is_admin'):

                            if session.get('form_step') == 0:
                                session['other_user_id'] = int(account)
                                session['form_step'] += 1
                                session['form_type'] = "ChangePassword"
                                return render_template('account.html', username=session.get('user'),
                                                       form_type=session.get('form_type'),
                                                       form_step=session.get('form_step'),
                                                       is_admin=session.get('is_admin'), api_key=session.get('api_key'),
                                                       current_user_id=session.get('other_user_id'))

                            elif session.get('form_step') == 1:
                                Cursor.execute('SELECT * FROM users WHERE user_id = %s', (session.get('other_user_id'),))
                                User = Cursor.fetchone()

                                if request.form['New_Password'] != request.form['New_Password_Retype']:
                                    return render_template('account.html', username=session.get('user'),
                                                           form_type=session.get('form_type'),
                                                           form_step=session.get('form_step'),
                                                           is_admin=session.get('is_admin'),
                                                           error="Please make sure the \"New Password\" and \"Retype Password\" fields match.",
                                                           api_key=session.get('api_key'),
                                                           current_user_id=session.get('other_user_id'))

                                else:
                                    Password_Security_Requirements_Check = check_security_requirements(request.form['New_Password'])

                                    if not Password_Security_Requirements_Check:
                                        return render_template('account.html', username=session.get('user'),
                                                               form_type=session.get('form_type'),
                                                               form_step=session.get('form_step'),
                                                               is_admin=session.get('is_admin'), requirement_error=[
                                                "The supplied password does not meet security requirements. Please make sure the following is met:",
                                                "- The password is longer that 8 characters.",
                                                "- The password contains 1 or more UPPERCASE and 1 or more lowercase character.",
                                                "- The password contains 1 or more number.",
                                                "- The password contains one or more special character. Ex. @."],
                                                               api_key=session.get('api_key'),
                                                               current_user_id=session.get('other_user_id'))

                                    else:
                                        password = generate_password_hash(request.form['New_Password'])
                                        Cursor.execute('UPDATE users SET password = %s WHERE user_id = %s', (password, User[0],))
                                        Connection.commit()
                                        return redirect(url_for('account'))

                            else:
                                return redirect(url_for('account'))

                        else:
                            return redirect(url_for('account'))

                else:
                    session["next_page"] = "account"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/account/apikey/get', methods=['POST'])
        def get_account_apikey():

            try:

                if session.get('user'):

                    def Create_Session_Based_JWT(ID, Username):
                        Expiry_Hours = API_Validity_Limit / 60
                        Expiry = datetime.utcnow() + timedelta(hours=Expiry_Hours)
                        payload = {"id": ID, "name": Username, "iat": datetime.utcnow(), "exp": Expiry, "nonce": secrets.token_hex(32)}
                        JWT = jwt.encode(payload, API_Secret, algorithm='HS256')
                        return JWT.decode('utf-8')

                    user_id = int(session.get('user_id'))

                    if user_id == session.get('user_id'):
                        Cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
                        User_Info = Cursor.fetchone()

                        if User_Info[5] and User_Info[6]:

                            try:
                                Decoded_Token = jwt.decode(User_Info[5], API_Secret, algorithm='HS256')
                                Cursor.execute('SELECT * FROM users ORDER BY user_id')
                                return render_template('account.html', username=session.get('user'),
                                                       form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                       results=Cursor.fetchall(), message="Current token is still valid.",
                                                       api_key=session.get('api_key'),
                                                       current_user_id=session.get('user_id'))

                            except:
                                API_Key = Create_Session_Based_JWT(User_Info[0], User_Info[1])
                                Cursor.execute('UPDATE users SET api_key = %s, api_generated_time = %s WHERE user_id = %s', (API_Key, General.Date(), User_Info[0],))
                                Connection.commit()
                                Message = f"New API Key generated for user ID {str(user_id)} by {session.get('user')}."
                                app.logger.warning(Message)
                                Create_Event(Message)
                                session['api_key'] = API_Key
                                Cursor.execute('SELECT * FROM users ORDER BY user_id')
                                return render_template('account.html', username=session.get('user'),
                                                       form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                       results=Cursor.fetchall(),
                                                       message="New API Key generated successfully.",
                                                       api_key=session.get('api_key'),
                                                       current_user_id=session.get('user_id'))

                        else:
                            API_Key = Create_Session_Based_JWT(User_Info[0], User_Info[1])
                            Cursor.execute('UPDATE users SET api_key = %s, api_generated_time = %s WHERE user_id = %s', (API_Key, General.Date(), User_Info[0],))
                            Connection.commit()
                            Message = f"New API Key generated for user ID {str(user_id)} by {session.get('user')}."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            session['api_key'] = API_Key
                            Cursor.execute('SELECT * FROM users ORDER BY user_id')
                            return render_template('account.html', username=session.get('user'),
                                                   form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                                   results=Cursor.fetchall(), message="New API Key generated successfully.",
                                                   api_key=session.get('api_key'), current_user_id=session.get('user_id'))

                    else:
                        Cursor.execute('SELECT * FROM users ORDER BY user_id')
                        return render_template('account.html', username=session.get('user'),
                                               form_step=session.get('form_step'), is_admin=session.get('is_admin'),
                                               results=Cursor.fetchall(),
                                               message="You are only able to generate API's for your own user.",
                                               api_key=session.get('api_key'), current_user_id=session.get('user_id'))

                else:
                    session["next_page"] = "account"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/account/delete/<accountid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_accounts_delete(accountid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':
                                user_id = int(accountid)
                                Cursor.execute("DELETE FROM users WHERE user_id = %s;", (user_id,))
                                Connection.commit()
                                User = Authentication_Verified["Username"]
                                Message = f"User ID {str(user_id)} deleted by {User}."
                                app.logger.warning(Message)
                                Create_Event(Message)
                                return jsonify({"Message": f"Successfully deleted user {str(user_id)}."}), 200

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/account/delete/<accountid>', methods=['POST'])
        def delete_account(accountid):

            try:

                if session.get('user') and session.get('is_admin'):

                    def del_account(accountid):
                        user_id = int(accountid)
                        Cursor.execute("DELETE FROM users WHERE user_id = %s;", (user_id,))
                        Connection.commit()
                        Message = f"User ID {str(user_id)} deleted by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)

                    if "," in accountid:

                        for userid in accountid.split(","):
                            del_account(userid)

                    else:
                        del_account(accountid)

                    return redirect(url_for('account'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "account"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/account/disable/<accountid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_accounts_disable(accountid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':
                                user_id = int(accountid)
                                Cursor.execute('UPDATE users SET blocked = %s WHERE user_id = %s', ("True", user_id,))
                                Connection.commit()
                                User = Authentication_Verified["Username"]
                                Message = f"User ID {str(user_id)} blocked by {User}."
                                app.logger.warning(Message)
                                Create_Event(Message)
                                return jsonify({"Message": f"Successfully blocked user {str(user_id)}."}), 200

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/account/disable/<accountid>', methods=['POST'])
        def disable_account(accountid):

            try:

                if session.get('user') and session.get('is_admin'):

                    def dis_account(accountid):
                        user_id = int(accountid)
                        Cursor.execute('UPDATE users SET blocked = %s WHERE user_id = %s', ("True", user_id,))
                        Connection.commit()
                        Message = f"User ID {str(user_id)} blocked by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)

                    if "," in accountid:

                        for userid in accountid.split(","):
                            dis_account(userid)

                    else:
                        dis_account(accountid)

                    return redirect(url_for('account'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "account"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/account/enable/<accountid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_accounts_enable(accountid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':
                                user_id = int(accountid)
                                Cursor.execute('UPDATE users SET blocked = %s WHERE user_id = %s', ("False", user_id,))
                                Connection.commit()
                                User = Authentication_Verified["Username"]
                                Message = f"User ID {str(user_id)} unblocked by {User}."
                                app.logger.warning(Message)
                                Create_Event(Message)
                                return jsonify({"Message": f"Successfully unblocked user {str(user_id)}."}), 200

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/account/enable/<accountid>', methods=['POST'])
        def enable_account(accountid):

            try:

                if session.get('user') and session.get('is_admin'):

                    def enble_account(accountid):
                        user_id = int(accountid)
                        Cursor.execute('UPDATE users SET blocked = %s WHERE user_id = %s', ("False", user_id,))
                        Connection.commit()
                        Message = f"User ID {str(user_id)} unblocked by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)

                    if "," in accountid:

                        for userid in accountid.split(","):
                            enble_account(userid)

                    else:
                        enble_account(accountid)

                    return redirect(url_for('account'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "account"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/account/demote/<accountid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_accounts_demote(accountid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':
                                user_id = int(accountid)
                                Cursor.execute('UPDATE users SET is_admin = %s WHERE user_id = %s', ("False", user_id,))
                                Connection.commit()
                                User = Authentication_Verified["Username"]
                                Message = f"Privileges for user ID {str(user_id)} demoted by {User}."
                                app.logger.warning(Message)
                                Create_Event(Message)
                                return jsonify({"Message": f"Successfully demoted user {str(user_id)}."}), 200

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/account/demote/<accountid>', methods=['POST'])
        def demote_account(accountid):

            try:

                if session.get('user') and session.get('is_admin'):

                    def dem_account(accountid):
                        user_id = int(accountid)
                        Cursor.execute('UPDATE users SET is_admin = %s WHERE user_id = %s', ("False", user_id,))
                        Connection.commit()
                        Message = f"Privileges for user ID {str(user_id)} demoted by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)

                    if "," in accountid:

                        for userid in accountid.split(","):
                            dem_account(userid)

                    else:
                        dem_account(accountid)

                    return redirect(url_for('account'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "account"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/account/promote/<accountid>', methods=['POST'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_accounts_promote(accountid):

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified["Token"]:

                        if Authentication_Verified["Admin"]:

                            if request.method == 'POST':
                                user_id = int(accountid)
                                Cursor.execute('UPDATE users SET is_admin = %s WHERE user_id = %s', ("True", user_id,))
                                Connection.commit()
                                User = Authentication_Verified["Username"]
                                Message = f"Privileges for user ID {str(user_id)} promoted by {User}."
                                app.logger.warning(Message)
                                Create_Event(Message)
                                return jsonify({"Message": f"Successfully promoted user {str(user_id)}."}), 200

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified["Message"]:
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/account/promote/<accountid>', methods=['POST'])
        def promote_account(accountid):

            try:

                if session.get('user') and session.get('is_admin'):

                    def pro_account(accountid):
                        user_id = int(accountid)
                        Cursor.execute('UPDATE users SET is_admin = %s WHERE user_id = %s', ("True", user_id,))
                        Connection.commit()
                        Message = f"Privileges for user ID {str(user_id)} promoted by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)

                    if "," in accountid:

                        for userid in accountid.split(","):
                            pro_account(userid)

                    else:
                        pro_account(accountid)

                    return redirect(url_for('account'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "account"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/account', methods=['GET'])
        def account():

            try:

                if session.get('user'):

                    if session.get('is_admin'):
                        session['form_step'] = 0
                        session['form_type'] = ""
                        session['other_user_id'] = 0
                        Cursor.execute('SELECT * FROM users ORDER BY user_id')
                        return render_template('account.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), api_key=session.get('api_key'), current_user_id=session.get('user_id'), Account_Filters=Account_Filters)

                    else:
                        return render_template('account.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), api_key=session.get('api_key'), current_user_id=session.get('user_id'), Account_Filters=Account_Filters)

                else:
                    session["next_page"] = "account"
                    return redirect(url_for('no_session'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/account/filtered', methods=['GET', 'POST'])
        def account_filtered():

            try:

                if session.get('is_admin') and session.get('is_admin'):
                    session['form_step'] = 0
                    session['form_type'] = ""
                    session['other_user_id'] = 0
            
                    if 'filter' in request.args and 'filtervalue' in request.args:
                        Filter = str(request.args['filter'])
                        Filter_Value = str(request.args['filtervalue'])

                        if "ID" in Filter:
                            Filter_Value = int(Filter_Value)

                        if Filter in Account_Filters:
                            Converted_Filter = Filter.lower().replace(" ", "_")
                        
                            if type(Filter_Value) == int:
                                Cursor.execute(f"SELECT * FROM users WHERE {Converted_Filter} = {Filter_Value} ORDER BY user_id DESC LIMIT 1000")

                            elif (type(Filter_Value) == str and not any(char in Filter_Value for char in Bad_Characters)):
                                Cursor.execute(f"SELECT * FROM users WHERE {Converted_Filter} = \'{Filter_Value}\' ORDER BY user_id DESC LIMIT 1000")
                            
                            else:
                                return redirect(url_for('account'))

                            return render_template('account.html', username=session.get('user'), form_step=session.get('form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), api_key=session.get('api_key'), current_user_id=session.get('user_id'), Filter_Name=Filter, Filter_Value=Filter_Value, Finding_Types=Finding_Types, Account_Filters=Account_Filters)

                        else:
                            return redirect(url_for('account'))

                    else:
                        return redirect(url_for('account'))

                else:

                    if not session.get('user'):
                        session["next_page"] = "account"
                        return redirect(url_for('no_session'))

                    else:
                        return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/accounts')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_account_details():

            try:

                if 'Authorization' in request.headers:
                    Auth_Token = request.headers['Authorization'].replace("Bearer ", "")
                    Authentication_Verified = API_verification(Auth_Token)

                    if Authentication_Verified.get("Token"):

                        if Authentication_Verified["Admin"]:

                            if request.method == 'GET':

                                if request.is_json:
                                    Content = request.get_json()
                                    data = {}
                                    Safe_Content = {}

                                    for Item in ["ID", "Username", "Blocked", "Administrative Rights"]:

                                        if Item in Content:

                                            if any(char in Item for char in Bad_Characters):
                                                return jsonify({"Error": f"Bad characters detected in the {Item} field."}), 500

                                            if Item == "ID":

                                                if type(Content[Item]) != int:
                                                    return jsonify({"Error": f"The ID provided is not an integer."}), 500

                                                Safe_Content["user_id"] = Content[Item]

                                            elif Item == "Administrative Rights":
                                                Safe_Content["is_admin"] = Content[Item]

                                            else:
                                                Safe_Content[Item.lower()] = Content[Item]

                                    if len(Safe_Content) > 1:
                                        Select_Query = "SELECT * FROM users WHERE "

                                        for Item_Key, Item_Value in sorted(Safe_Content.items()):
                                            Select_Query += f"{Item_Key} = '{Item_Value}'"

                                            if Item_Key != sorted(Safe_Content.keys())[-1]:
                                                Select_Query += " and "

                                            else:
                                                Select_Query += ";"

                                        Cursor.execute(Select_Query)

                                    elif len(Safe_Content) == 1:
                                        Key = list(Safe_Content.keys())[0]
                                        Val = list(Safe_Content.values())[0]
                                        Cursor.execute(f"SELECT * FROM users WHERE {Key} = '{Val}';")

                                    else:
                                        return jsonify({"Error": "No valid fields found in request."}), 500

                                    for User in Cursor.fetchall():
                                        data[User[0]] = [{"Username": User[1], "Blocked": User[3], "Administrative Rights": User[4]}]

                                    return jsonify(data), 200

                                else:
                                    data = {}
                                    Cursor.execute('SELECT * FROM users ORDER BY user_id DESC LIMIT 1000')

                                    for User in Cursor.fetchall():
                                        data[User[0]] = [{"Username": User[1], "Blocked": User[3], "Administrative Rights": User[4]}]

                                    return jsonify(data), 200

                            else:
                                return jsonify({"Error": "Method not allowed."}), 500

                        else:
                            return jsonify({"Error": "Insufficient privileges."}), 500

                    else:

                        if Authentication_Verified.get("Message"):
                            return jsonify({"Error": Authentication_Verified["Message"]}), 500

                        else:
                            return jsonify({"Error": "Unauthorised."}), 500

                else:
                    return jsonify({"Error": "Missing Authorization header."}), 500

            except Exception as e:
                app.logger.error(e)

        Screenshot_Checker()
        app.run(debug=Application_Details[0], host=Application_Details[1], port=Application_Details[2], threaded=True, ssl_context=context)

    except Exception as e:
        sys.exit(str(e))
