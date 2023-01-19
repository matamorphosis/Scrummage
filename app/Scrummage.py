#!/usr/bin/env python3
# Author: matamorphosis
# License: GPL-3.0

if __name__ == '__main__':

    try:
        from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify
        from flask_compress import Compress
        from flask_wtf.csrf import CSRFProtect, CSRFError
        from signal import signal, SIGINT
        from functools import wraps
        from datetime import datetime, timedelta
        from werkzeug.security import generate_password_hash, check_password_hash
        from crontab import CronTab
        from logging.handlers import RotatingFileHandler
        from ratelimiter import RateLimiter
        import os, sys, plugin_caller, plugin_verifier, plugin_definitions, getpass, pathlib, time, sys, threading, html, secrets, jwt, logging, pyotp, plugins.common.General as General, plugins.common.Common as Common

        Finding_Types: list = sorted(["Darkweb Link", "Company Details", "Blockchain - Address", "Blockchain - Transaction",
                         "BSB Details", "Certificate", "Search Result", "Cloud Storage - Azure Blob", "Cloud Storage - AWS S3", "Credentials", "Domain Information", "Email Information",
                         "Social Media - Media", "Social Media - Page", "Social Media - Person", "Social Media - Group",
                         "Social Media - Place", "Application", "Account", "Account Source", "Publication", "Phishing", "Phone Details"
                         "Repository", "Forum", "News Report", "Torrent", "Vehicle Details", "Domain Spoof", "Data Leakage", "Exploit",
                         "Economic Details", "Malware", "Malware Report", "Web Application Architecture", "IP Address Information", "Wiki Page", "Hash"])
        Result_Filters: tuple = ("Result ID", "Task ID", "Title", "Plugin", "Status", "Domain", "Link", "Created At", "Updated At", "Result Type")
        Standard_Safe_Chars: list = ["-", "(", ")", "*", "/", ".", ",", ":", "@", "=", "[", "]", " "]
        Restricted_Safe_Chars: list = ["-", ":", ".", ",", " "]
        Task_Filters: tuple = ("Task ID", "Query", "Plugin", "Description", "Frequency", "Task Limit", "Status", "Created At", "Updated At")
        Event_Filters: tuple = ("Event ID", "Description", "Created At")
        Account_Filters: tuple = ("User ID", "Username", "Blocked", "Is Admin")
        Identity_Filters: tuple = ("Identity ID", "Firstname", "Middlename", "Surname", "Fullname", "Username", "Email", "Phone")
        Thread_In_Use = None
        SS_Thread_In_Use = None
        Version: str = "3.9"

        try:
            Scrummage_Working_Directory = pathlib.Path(sys.argv[0]).parent.absolute()
            SWD_Iterator: int = int()

            while str(Scrummage_Working_Directory) != str(os.getcwd()):

                if SWD_Iterator == int():
                    print(f"[i] Scrummage has been called from outside the Scrummage directory, changing the working directory to {str(Scrummage_Working_Directory)}.")
                    os.chdir(Scrummage_Working_Directory)
                    SWD_Iterator += 1

                else:
                    sys.exit(f'{Common.Date()} Error setting the working directory.')

        except:
            sys.exit(f'{Common.Date()} Error setting the working directory.')

        Valid_Plugins = plugin_definitions.Get(Scrummage_Working_Directory)
        Org_Preset_to_Regex_Mapping: dict = {"domain": "Domain", "website": "URL", "identity_phones": "Phone", "identity_emails": "Email", "identity_usernames": "Username", "IP": "IP"}

        def No_Limit_Plugins():
            Plugin_Names: list = list()

            for Key, Value in Valid_Plugins.items():

                if not Value["Requires_Limit"]:
                    Plugin_Names.append(Key)

            return Plugin_Names

        try:
            File_Path = os.path.dirname(os.path.realpath('__file__'))
            app = Flask(__name__, instance_path=os.path.join(File_Path, 'static/protected'))
            Compress(app)
            csrf = CSRFProtect(app)
            
            app.config.update(
                SESSION_COOKIE_SECURE=True,
                SESSION_COOKIE_HTTPONLY=True,
                SESSION_COOKIE_SAMESITE='Strict',
            )
            app.permanent_session_lifetime = timedelta(minutes=5)

        except:
            app.logger.fatal(f'{Common.Date()} Startup error, ensure all necessary libraries are imported and installed.')
            sys.exit()

        Application_Details: list = Common.Configuration(Core=True).Load_Configuration(Object="web_app", Details_to_Load=["debug", "host", "port", "certificate_file", "key_file", "api_secret", "api_validity_minutes", "api_max_calls", "api_period_in_seconds"])
        API_Secret: str = Application_Details[5]
        API_Validity_Limit: int = Application_Details[6]
        Minimum_API_Limit: int = 60

        if API_Validity_Limit < Minimum_API_Limit:
            app.logger.fatal(f"{Common.Date()} API Validity Limit must be greater than or equal to {Minimum_API_Limit}.")
            sys.exit()

        API_Max_Calls = Application_Details[7]
        API_Period = Application_Details[8]

        def handler(signal_received, frame):
            print('[i] CTRL-C detected. Shutting program down.')

            if Connection:
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
            Connection = Common.Configuration(Output=True).Load_Configuration(Postgres_Database=True, Object="postgresql")
            Cursor = Connection.cursor()

        except:
            app.logger.fatal(f'{Common.Date()} Failed to load main database, please make sure the database details are added correctly to the configuration, and the PostgreSQL service is running.')
            sys.exit()

        try:
            Cursor.execute('UPDATE tasks SET status = %s', ("Stopped",))
            Connection.commit()

        except:
            app.logger.fatal(f'{Common.Date()} Startup error - database issue.')
            sys.exit()

        try:
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=Application_Details[3], keyfile=Application_Details[4])

        except Exception as e:
            app.logger.fatal(f'{Common.Date()} Error initiating SSL. {str(e)}.')
            sys.exit()

        class User:

            def __init__(self, username, password):
                self.username = username
                self.password = password

            def authenticate(self) -> dict:
                Cursor.execute('SELECT * FROM users WHERE username = %s', (self.username,))
                User_Details = Cursor.fetchone()

                if User_Details:
                    Password_Check = check_password_hash(User_Details[2], self.password)

                    if not Password_Check:

                        if not self.username.isalnum():
                            Message = f"Failed login attempt for the provided user {str(User_Details[1])} with a password that contains potentially dangerous characters."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            return {"Message": True}

                        else:
                            Message = f"Failed login attempt for user {str(User_Details[1])}."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            return {"Message": True}

                    else:

                        if not User_Details[3]:
                            self.ID = User_Details[0]
                            self.authenticated: bool = True
                            self.admin = User_Details[4]
                            self.API = User_Details[5]
                            self.MFA = User_Details[8]
                            return {"ID": self.ID, "Username": User_Details[1], "Admin": self.admin, "API": self.API, "MFA": self.MFA, "Status": True}

                        else:
                            Message = f"Login attempted by user ID {str(User_Details[0])} who is currently blocked."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            return {"Message": True}

                else:

                    if not self.username.isalnum():
                        Message: str = "Failed login attempt for a provided username that contained potentially dangerous characters."
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
                            Cursor.execute('UPDATE users SET api_key = %s, api_generated_time = %s WHERE user_id = %s', (API_Key, Common.Date(), self.ID,))
                            Connection.commit()
                            Message = f"New API Key generated for user ID {str(self.ID)}."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            return {"Key": API_Key, "Message": Message}

                    except jwt.ExpiredSignatureError:
                        API_Key = Create_JWT(self)
                        Cursor.execute('UPDATE users SET api_key = %s, api_generated_time = %s WHERE user_id = %s', (API_Key, Common.Date(), self.ID,))
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
                        return {"Token": False, "Admin": False, "Username": User_Details[1], "Message": "Token blocked."}

                else:
                    return {"Token": False, "Admin": False, "Message": "Invalid token."}

            except jwt.ExpiredSignatureError:
                return {"Token": False, "Admin": False, "Message": "Token expired."}

            except jwt.DecodeError:
                return {"Token": False, "Admin": False, "Message": "Failed to decode token."}

            except jwt.InvalidTokenError:
                return {"Token": False, "Admin": False, "Message": "Invalid token."}

        def Output_API_Checker():

            try:
                Full_List: dict = dict()

                for API_Key, API_Value in Valid_Plugins.items():

                    if API_Value["Requires_Configuration"]:
                        Result = plugin_verifier.Plugin_Verifier(API_Key, int(), str(), int()).Verify_Plugin(Scrummage_Working_Directory, Load_Config_Only=True)
                        Full_List[API_Key] = Result

                if len(Full_List) > int():
                    return Full_List

                else:
                    return None

            except Exception as e:
                app.logger.error(e)

        def Create_Event(Description: str = str()):

            try:
                Cursor.execute("INSERT INTO events (description, created_at) VALUES (%s,%s)", (Description, Common.Date()))
                Connection.commit()

            except Exception as e:
                app.logger.error(e)

        def Validator(String_to_Check: str = str(), Safe_Characters: list = list(), Safe_Spaces: bool = True) -> bool:

            try:
                String_to_Check = str(String_to_Check)
                whitelist: list = Common.Alnum_List()
                whitelist.extend(Safe_Characters)

                if not Safe_Spaces and " " in String_to_Check:
                    return False
            
                for char in String_to_Check:

                    if char in whitelist:

                        if len(char) == 1 and not char.isalnum() and char not in (".", ","):
                            double_char = f"{char}{char}"

                            if double_char in String_to_Check:
                                return False

                    else:
                        return False

                return True

            except Exception as e:
                app.logger.error(e)

        def login_requirement(f):

            try:
                @wraps(f)
                def wrap(*args, **kwargs):

                    if session.get('user'):
                        return f(*args, **kwargs)

                    else:
                    
                        if request.url.endswith("/logout"):
                            session["next_page"] = url_for("dashboard")
                            
                        elif "/tasks/run" in request.url:
                            session["next_page"] = url_for("tasks")
                        
                        else:
                            session["next_page"] = request.url
                        
                        return redirect(url_for('no_session'))

                return wrap

            except Exception as e:
                app.logger.error(e)

        def admin_requirement(f):

            try:
                @wraps(f)
                def wrap(*args, **kwargs):

                    if session.get('is_admin'):
                        return f(*args, **kwargs)

                    else:
                        Redirects = {"result": url_for('results'), "task": url_for('tasks'), "setting": url_for('account'), "account": url_for('account')}

                        for Redirect_Key, Redirect_Value in Redirects.items():
                        
                            if Redirect_Key in request.url:
                                return redirect(Redirect_Value)

                        return redirect(url_for('dashboard'))

                return wrap

            except Exception as e:
                app.logger.error(e)

        def api_auth_requirement(f):

            try:
                @wraps(f)
                def wrap(*args, **kwargs):

                    if 'Authorization' in request.headers:
                        Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                        Authentication_Verified = API_verification(Auth_Token)

                        if Authentication_Verified["Token"]:
                            return f(*args, **kwargs)

                        else:

                            if Authentication_Verified["Message"]:
                                return jsonify({"Error": Authentication_Verified["Message"]}), 500

                            else:
                                return jsonify({"Error": "Unauthorised."}), 500

                    else:
                        return jsonify({"Error": "Missing Authorization header."}), 500

                return wrap

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        def api_admin_requirement(f):

            try:
                @wraps(f)
                def wrap(*args, **kwargs):

                    if 'Authorization' in request.headers:
                        Auth_Token = request.headers['Authorization'].replace("Bearer ", "").replace("bearer ", "")
                        Authentication_Verified = API_verification(Auth_Token)

                        if Authentication_Verified["Admin"]:
                            return f(*args, **kwargs)

                        else:
                            return jsonify({"Error": "Insufficient permissions."}), 500

                    else:
                        return jsonify({"Error": "Missing Authorization header."}), 500

                return wrap

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.errorhandler(CSRFError)
        def handle_csrf_error(e):
            
            if session.get('user'):
                
                if request.url.endswith("/logout"):
                    session["next_page"] = url_for("dashboard")
                    
                elif "tasks" in request.url:
                    return redirect(url_for('tasks'))

                elif "results" in request.url:
                    return redirect(url_for('results'))

                elif "identities" in request.url:
                    return redirect(url_for('identities'))
                
                elif "settings" in request.url:
                    return redirect(url_for('settings'))

                else:
                    return redirect(url_for('dashboard'))

            else:
                return redirect(url_for('no_session'))

        @app.errorhandler(400)
        @login_requirement
        def bad_request(e):

            try:
                return render_template('bad_request.html'), 400

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        @app.errorhandler(404)
        @login_requirement
        def page_not_found(e):

            try:
                return render_template('404.html', username=session.get('user')), 404

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        @app.errorhandler(405)
        @login_requirement
        def no_method(e):

            try:
                return render_template('nomethod.html', username=session.get('user'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        app.register_error_handler(400, bad_request)
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
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def login():

            try:

                if request.method == 'POST':
                    time.sleep(1)

                    if 'username' in request.form and 'password' in request.form:

                        if not request.form['username'].isalnum():
                            return render_template('index.html', error="Login Unsuccessful.")

                        Current_User = User(request.form['username'], request.form['password']).authenticate()

                        if Current_User and all(User_Item in Current_User for User_Item in ['Username', 'Status', 'MFA']):

                            if Current_User.get('MFA') and Current_User['MFA'] == "true":
                                session['user_id'] = Current_User.get('ID')
                                return redirect(url_for('mfa_login'))

                            else:
                                session['dashboard-refresh']: int = int()
                                session['user_id'] = Current_User.get('ID')
                                session['user'] = Current_User.get('Username')
                                session['is_admin'] = Current_User.get('Admin')
                                session['api_key'] = Current_User.get('API')
                                session['task_frequency']: str = str()
                                session['task_description']: str = str()
                                session['task_limit']: int = int()
                                session['task_query']: str = str()
                                session['task_id']: str = str()
                                Message = f"Successful login from {Current_User.get('Username')}."
                                app.logger.warning(Message)
                                Create_Event(Message)

                                if session.get("next_page"):
                                    Redirect = session.get("next_page")
                                    session["next_page"] == str()
                                    return redirect(Redirect)

                                else:
                                    return redirect(url_for('dashboard'))

                        elif Current_User and 'Message' in Current_User:
                            return render_template('index.html', error='Login Unsuccessful.')

                        else:
                            return render_template('index.html')

                    else:
                        return render_template('index.html')

                else:
                    session['user_id']: str = str()
                    return render_template('index.html')

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        @app.route('/login/mfa', methods=['POST', 'GET'])
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def mfa_login():

            try:

                if request.method == 'POST':
                    time.sleep(1)
                    user_id = int(session.get('user_id'))
                    Cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
                    User_Info = Cursor.fetchone()
                    TOTP = pyotp.TOTP(User_Info[7])

                    if request.form.get("mfa_token") and (request.form["mfa_token"] == TOTP.now()):
                        session['dashboard-refresh']: int = int()
                        session['user_id'] = User_Info[0]
                        session['user'] = User_Info[1]
                        session['is_admin'] = User_Info[4]
                        session['api_key'] = User_Info[5]
                        session['task_frequency']: str = str()
                        session['task_description']: str = str()
                        session['task_limit']: int = int()
                        session['task_query']: str = str()
                        session['task_id']: str = str()
                        Message = f"Successful login from {User_Info[1]}."
                        app.logger.warning(Message)
                        Create_Event(Message)

                        if session.get("next_page"):
                            Redirect = session.get("next_page")
                            session["next_page"] == str()
                            return redirect(Redirect)

                        else:
                            return redirect(url_for('dashboard'))

                    else:
                        return render_template('index.html', mfa_form=True, error="Invalid MFA token.")

                else:

                    if session.get('user_id'):
                        return render_template('index.html', mfa_form=True)

                    else:
                        return redirect(url_for('index'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        @app.route('/api/auth', methods=['POST'])
        @csrf.exempt
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
                return redirect(url_for('login'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        @app.route('/tasks/inputs/check', methods=['GET', 'POST'])
        @login_requirement
        @admin_requirement
        def check_input():

            try:
                return render_template('check_input.html', username=session.get('user'), is_admin=session.get('is_admin'), Configurations=Output_API_Checker().items())

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/tasks/inputs/check')
        @api_auth_requirement
        @api_admin_requirement
        def api_check_input():

            try:

                if request.method == 'GET':
                    Purified: dict = dict()

                    for Key, Value in Output_API_Checker().items():

                        if Value:
                            Purified[Key]: bool = True

                        else:
                            Purified[Key]: bool = bool()

                    return jsonify({"Inputs": Purified})

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks/outputs/check', methods=['GET', 'POST'])
        @login_requirement
        @admin_requirement
        def check_output():

            try:

                def Load_Config(Conn_Obj, Type):

                    if Type in ["postgresql", "scumblr"]:
                        Config_Response = Conn_Obj.Load_Configuration(Object=Type, Postgres_Database=True)

                    else:
                        Config_Response = Common.Load_Output(Conn_Obj, Type)

                    if Config_Response:
                        return True

                    else:
                        return False

                Connector_Object = Common.Configuration(Output=True)
                CSV = Load_Config(Connector_Object, "csv")
                DD = Load_Config(Connector_Object, "defectdojo")
                DOCX = Load_Config(Connector_Object, "docx")
                Email = Load_Config(Connector_Object, "email")
                Elastic = Load_Config(Connector_Object, "elasticsearch")
                Main_DB = Load_Config(Connector_Object, "postgresql")
                JIRA = Load_Config(Connector_Object, "jira")
                RTIR = Load_Config(Connector_Object, "rtir")
                Slack = Load_Config(Connector_Object, "slack")
                Scumblr = Load_Config(Connector_Object, "scumblr")
                return render_template('check_output.html', username=session.get('user'), Configurations=[["Main Database", Main_DB], ["CSV Report", CSV], ["DefectDojo", DD], ["DOCX Report", DOCX], ["Email", Email], ["ElasticSearch", Elastic], ["JIRA", JIRA], ["RTIR", RTIR], ["Slack Channel Notification", Slack], ["Scumblr Database", Scumblr]], is_admin=session.get('is_admin'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/tasks/outputs/check')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_check_output():

            try:

                if request.method == 'GET':

                    def Load_Config(Conn_Obj, Type):

                        if Type in ["postgresql", "scumblr"]:
                            Config_Response = Conn_Obj.Load_Configuration(Object=Type, Postgres_Database=True)

                        else:
                            Config_Response = Common.Load_Output(Conn_Obj, Type)

                        if Config_Response:
                            return True

                        else:
                            return False

                    Connector_Object = Common.Configuration(Output=True)
                    CSV = Load_Config(Connector_Object, "csv")
                    DD = Load_Config(Connector_Object, "defectdojo")
                    DOCX = Load_Config(Connector_Object, "docx")
                    Email = Load_Config(Connector_Object, "email")
                    Elastic = Load_Config(Connector_Object, "elasticsearch")
                    Main_DB = Load_Config(Connector_Object, "postgresql")
                    JIRA = Load_Config(Connector_Object, "jira")
                    RTIR = Load_Config(Connector_Object, "rtir")
                    Slack = Load_Config(Connector_Object, "slack")
                    Scumblr = Load_Config(Connector_Object, "scumblr")
                    return jsonify({"Main Database": bool(Main_DB), "CSV Report": bool(CSV), "DefectDojo": bool(DD), "DOCX Report": bool(DOCX), "Email": bool(Email), "ElasticSearch": bool(Elastic), "JIRA": bool(JIRA), "RTIR": bool(RTIR), "Slack Channel Notification": bool(Slack), "Scumblr Database": bool(Scumblr)}), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/static/protected/<path:filename>')
        @login_requirement
        def protected(filename):

            try:
                Risk_Level = Common.Configuration(Core=True).Load_Configuration(Object="web_scraping", Details_to_Load=["risk_level", "automated_screenshots"])
                Risk_Level = Risk_Level[0]

                if any(filename.endswith(Ext) for Ext in [".html", ".json", ".csv", ".png", ".docx"]):

                    if filename.endswith('.html') and Risk_Level == 0:
                        return render_template('restricted.html', html_risk_level=True, username=session.get('user'))

                    else:
                        return send_from_directory(os.path.join(app.instance_path, ''), filename)

                else:
                    return render_template('restricted.html', html_risk_level=False, username=session.get('user'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.after_request
        def apply_response_headers(response):

            try:
                response.headers["X-Frame-Options"]: str = "DENY"
                response.headers["X-XSS-Protection"]: str = "1; mode=block"
                response.headers["X-Content-Type"]: str = "nosniff"
                response.headers["Server"]: str = str()
                response.headers["Pragma"]: str = "no-cache"
                response.headers["Cache-Control"]: str = "no-cache, no-store, must-revalidate, pre-check=0, post-check=0, max-age=0, s-maxage=0"
                response.headers["Expires"]: str = "0"
                return response

            except Exception as e:
                app.logger.error(e)

        @app.route('/api/result/screenshot/<resultid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_results_screenshot(resultid):
            global SS_Thread_In_Use

            try:

                if Permit_Screenshots:

                    if request.method == 'POST':
                        ss_id = int(resultid)
                        Chrome_Config = Common.Configuration(Core=True).Load_Configuration(Object="google_chrome", Details_to_Load=["application_path", "chromedriver_path"])

                        if all(os.path.exists(Config) for Config in Chrome_Config):
                            Cursor.execute('SELECT screenshot_url FROM results WHERE result_id = %s', (ss_id,))
                            SS_URL = Cursor.fetchone()
                            Cursor.execute('SELECT screenshot_requested FROM results WHERE result_id = %s', (ss_id,))
                            SS_Req = Cursor.fetchone()

                            if not SS_URL[0] and not SS_Req[0]:
                            
                                def Get_Screenshot(Inner_File_Path, Inner_SS_ID, User_Inner):
                                    General.Screenshot(Inner_File_Path, Screenshot_ID=Inner_SS_ID, Screenshot_User=User_Inner).Grab_Screenshot()

                                def Threaded_Task_Runner(Thread_File_Path, Thread_SS_ID, Thread_User):
                                    global SS_Thread_In_Use
                                    
                                    if SS_Thread_In_Use and SS_Thread_In_Use.is_alive():
                                        Previous_SS_Thread = SS_Thread_In_Use
                                        SS_Thread_In_Use = threading.Thread(target=Get_Screenshot, args=(Thread_File_Path, Thread_SS_ID, Thread_User))
                                        SS_Thread_In_Use.start()
                                        Previous_SS_Thread.join()
                                        SS_Thread_In_Use.join()

                                if SS_Thread_In_Use and SS_Thread_In_Use.is_alive():
                                    threading.Thread(target=Threaded_Task_Runner, args=(File_Path, ss_id, str(session.get('user')))).start()
                                    return jsonify({"Message": f"Successfully queued screenshot for {str(ss_id)}."}), 200
                                        
                                else:
                                    SS_Thread_In_Use = threading.Thread(target=Get_Screenshot, args=(File_Path, ss_id, str(session.get('user'))))
                                    SS_Thread_In_Use.start()
                                    return jsonify({"Message": f"Successfully requested screenshot for {str(ss_id)}."}), 200

                            else:
                                jsonify({"Error": f"Screenshot already requested for result id {str(ss_id)}."})

                        else:
                            return jsonify({"Error": "Screenshot request terminated. Google Chrome and/or Chrome Driver have either not been installed or configured properly."}), 500

                    else:
                        return jsonify({"Error": "Method not allowed."}), 500

                else:
                    return jsonify({"Error": "Screenshots currently disabled due to a mismatch between Google Chrome and Chrome Driver versions on the server."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/results/screenshot/<resultid>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def screenshot(resultid):
            global SS_Thread_In_Use

            try:

                if Permit_Screenshots:
                    ss_id = int(resultid)
                    Chrome_Config = Common.Configuration(Core=True).Load_Configuration(Object="google_chrome", Details_to_Load=["application_path", "chromedriver_path"])

                    if all(os.path.exists(Config) for Config in Chrome_Config):
                        Cursor.execute('SELECT screenshot_url FROM results WHERE result_id = %s', (ss_id,))
                        SS_URL = Cursor.fetchone()
                        Cursor.execute('SELECT screenshot_requested FROM results WHERE result_id = %s', (ss_id,))
                        SS_Req = Cursor.fetchone()
                        Append_Mode: bool = bool()

                        if not SS_Req[0]:
                        
                            if SS_URL[0]:
                                Append_Mode: bool = True
                        
                            def Get_Screenshot(Inner_File_Path, Inner_SS_ID, User_Inner, Append_Mode_Inner):
                                General.Screenshot(Inner_File_Path, Screenshot_ID=Inner_SS_ID, Screenshot_User=User_Inner, Append_Mode=Append_Mode_Inner).Grab_Screenshot()

                            def Threaded_Task_Runner(Thread_File_Path, Thread_SS_ID, Thread_User, Thread_Append_Mode):
                                global SS_Thread_In_Use
                                
                                if SS_Thread_In_Use and SS_Thread_In_Use.is_alive():
                                    Previous_SS_Thread = SS_Thread_In_Use
                                    SS_Thread_In_Use = threading.Thread(target=Get_Screenshot, args=(Thread_File_Path, Thread_SS_ID, Thread_User, Thread_Append_Mode))
                                    SS_Thread_In_Use.start()
                                    Previous_SS_Thread.join()
                                    SS_Thread_In_Use.join()

                            if SS_Thread_In_Use and SS_Thread_In_Use.is_alive():
                                threading.Thread(target=Threaded_Task_Runner, args=(File_Path, ss_id, str(session.get('user')), Append_Mode)).start()
                                    
                            else:
                                SS_Thread_In_Use = threading.Thread(target=Get_Screenshot, args=(File_Path, ss_id, str(session.get('user')), Append_Mode))
                                SS_Thread_In_Use.start()

                        else:
                            app.logger.warning(f"Screenshot already requested for result id {str(ss_id)}.")

                    else:
                        app.logger.warning(f"Either Google Chrome or Chrome Driver have not been installed / configured. Screenshot request terminated.")                    

                else:
                    app.logger.warning("Screenshots currently disabled due to a mismatch between Google Chrome and Chrome Driver versions on the server.")

                session["result_ss_request_message"] = f"Screenshot requested for result {str(resultid)}."
                time.sleep(1.5)
                return redirect(url_for('result_details', resultid=resultid))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('result_details', resultid=resultid))

        def dashboard_colours():
            
            try:
                colors_blue = ["#00162b", "#001f3f", "#002952", "#003366", "#003d7a", "#00478d", "#0050a1", "#005ab4", "#0064c8", "#006edc", "#0078ef", "#0481ff", "#188bff", "#2b95ff", "#3f9fff", "#52a9ff", "#66b3ff", "#7abcff", "#8dc6ff", "#a1d0ff", "#b4daff", "#c8e4ff", "#dcedff", "#eff7ff"]
                colors_red = ["#2b0000", "#3f0000", "#520000", "#660000", "#7a0000", "#8d0000", "#a10000", "#b40000", "#c80000", "#dc0000", "#ef0000", "#ff0404", "#ff1818", "#ff2b2b", "#ff3f3f", "#ff5252", "#ff6666", "#ff7a7a", "#ff8d8d", "#ffa1a1"]
                return colors_blue + list(reversed(colors_red))

            except Exception as e:
                app.logger.error(e)
                return None

        @app.route('/dashboard/tasks', methods=['GET'])
        @login_requirement
        def tasks_dashboard():

            try:
                colors_original = dashboard_colours()
                most_common_tasks_labels: list = list()
                most_common_tasks_values: list = list()
                most_common_queries_labels: list = list()
                most_common_queries_values: list = list()
                most_common_frequencies_labels: list = list()
                most_common_frequencies_values: list = list()
                Cursor.execute("SELECT plugin, COUNT(*) AS counted FROM tasks WHERE plugin IS NOT NULL GROUP BY plugin ORDER BY counted DESC, plugin LIMIT 10;")
                most_common_tasks = Cursor.fetchall()
                Cursor.execute("SELECT query, COUNT(*) AS counted FROM tasks WHERE query IS NOT NULL GROUP BY query ORDER BY counted DESC, query LIMIT 10;")
                most_common_queries = Cursor.fetchall()
                Cursor.execute("SELECT frequency, COUNT(*) AS counted FROM tasks WHERE frequency IS NOT NULL AND frequency != '' GROUP BY frequency ORDER BY counted DESC, frequency LIMIT 10;")
                most_common_frequencies = Cursor.fetchall()

                for mc_task in most_common_tasks:
                    most_common_tasks_labels.append(mc_task[0])
                    most_common_tasks_values.append(mc_task[1])

                for mc_query in most_common_queries:
                    most_common_queries_labels.append(mc_query[0])
                    most_common_queries_values.append(mc_query[1])

                for mc_frequency in most_common_frequencies:
                    most_common_frequencies_labels.append(mc_frequency[0])
                    most_common_frequencies_values.append(mc_frequency[1])

                common_task_types = [most_common_tasks_labels, most_common_tasks_values, colors_original[:len(most_common_tasks_values)]]
                common_frequency_types = [most_common_frequencies_labels, most_common_frequencies_values, colors_original[:len(most_common_frequencies_values)]]
                common_query_types = [most_common_queries_labels, most_common_queries_values, colors_original[:len(most_common_queries_values)]]
                return render_template('dashboard.html', tasksdash=True, is_admin=session.get('is_admin'), username=session.get('user'), common_task_types=common_task_types, common_frequency_types=common_frequency_types, common_query_types=common_query_types, refreshrate=session.get('dashboard-refresh'), version=Version)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('dashboard'))

        @app.route('/dashboard/results', methods=['GET', 'POST'])
        @login_requirement
        def results_dashboard():

            try:
                Status: str = str()
                Review_Results: bool = True
                Closed_Results: bool = True

                if request.method == "POST":
                    
                    if request.form.get("reviewresults") and not request.form.get("closedresults"):
                        Status: str = "status != 'Closed'"
                        Closed_Results: bool = bool()

                    elif not request.form.get("reviewresults") and request.form.get("closedresults"):
                        Status: str = "status != 'Reviewing'"
                        Review_Results: bool = bool()

                    elif not request.form.get("reviewresults") and not request.form.get("closedresults"):
                        Status: str = "status: str = 'Open'"
                        Closed_Results: bool = bool()
                        Review_Results: bool = bool()

                labels = Finding_Types
                colors_original = dashboard_colours()
                colors = colors_original[:len(labels)]
                PSQL_Select_Query: str = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s;'
                Dendogram_Query_1: str = 'SELECT DISTINCT query FROM tasks;'
                Dendogram_Query_2: str = 'SELECT task_id FROM tasks WHERE query ILIKE %s;'

                if Status != str():
                    Dendogram_Query_3: str = 'SELECT DISTINCT result_type FROM results WHERE task_id = %s' + f' AND {Status};'
                    Dendogram_Query_4: str = 'SELECT domain, link FROM results WHERE result_type = %s' + f' AND {Status};'

                else:
                    Dendogram_Query_3: str = 'SELECT DISTINCT result_type FROM results WHERE task_id = %s;'
                    Dendogram_Query_4: str = 'SELECT domain, link FROM results WHERE result_type = %s;'

                Dendogram_Query_4: str = 'SELECT domain, link FROM results WHERE result_type = %s;'
                Dendogram_Data = {"children": list(), "name": "Scrummage"}
                open_values: list = list()
                closed_values: list = list()
                mixed_values: list = list()
                Use_Open: bool = True
                Use_Closed: bool = True
                Use_Mixed: bool = True
                Task_ID_Dict: dict = dict()

                Cursor.execute(Dendogram_Query_1)
                Dendogram_Main_Results = Cursor.fetchall()
                Dendogram_Condensed_Query_Dict: dict = dict()
                Condensed_List: list = list()

                for Query in Dendogram_Main_Results:
                    Query = Query[0]
                    Extracted_List = General.Convert_to_List(Query)

                    for Extracted_Item in Extracted_List:
                        Extracted_Item = Extracted_Item.replace("https://", "").replace("http://", "").replace("/", "")

                        if Extracted_Item not in Condensed_List:
                            Condensed_List.append(Extracted_Item)

                    if Query not in Task_ID_Dict:
                        Task_ID_Dict[Query]: list = list()

                    Like_Query = f"%{Query}%"
                    Cursor.execute(Dendogram_Query_2, (Like_Query,))
                    Results = Cursor.fetchall()
                    Task_ID_Dict[Query].extend(Results)

                for Inner_Query in Condensed_List:
                    Task_IDs: list = list()

                    if Inner_Query not in Dendogram_Condensed_Query_Dict:
                        Dendogram_Condensed_Query_Dict[Inner_Query]: dict = dict()

                    if Inner_Query in Task_ID_Dict:
                        New_Result_Types: list = list()

                        for Task_ID in Task_ID_Dict[Inner_Query]:
                            Task_ID = Task_ID[0]

                            if Task_ID not in Task_IDs:
                                Task_IDs.append(Task_ID)

                        for New_Task_ID in Task_IDs:
                            Cursor.execute(Dendogram_Query_3, (New_Task_ID,))
                            Result_Types = Cursor.fetchall()

                            for Result_Type in Result_Types:
                                Result_Type = Result_Type[0]

                                if Result_Type not in New_Result_Types:
                                    New_Result_Types.append(Result_Type)

                        for Result_Type in New_Result_Types:
                            Cursor.execute(Dendogram_Query_4, (Result_Type,))
                            Domains_and_Links = Cursor.fetchall()
                            Domain_Links_Dict: dict = dict()

                            for DL in Domains_and_Links:

                                if DL[0] not in Domain_Links_Dict:
                                    Domain_Links_Dict[DL[0]] = [DL[1]]

                                else:
                                    Domain_Links_Dict[DL[0]].append(DL[1])

                            if Result_Type not in Dendogram_Condensed_Query_Dict[Inner_Query]:
                                Dendogram_Condensed_Query_Dict[Inner_Query][Result_Type] = {"URL": url_for("results_filtered") + f"?Result+ID=&Task+ID=&Title=&Plugin=&Status=&Domain=&Link=&Created+At=&Updated+At=&Result+Type={Result_Type}&setfilter=Set+Filter", "Domain_Links": Domain_Links_Dict}

                        if len(Dendogram_Condensed_Query_Dict[Inner_Query]) == 0:
                            Dendogram_Condensed_Query_Dict[Inner_Query]["No Results"]: str = str()

                for Key in Dendogram_Condensed_Query_Dict.keys():
                    Child_List: list = list()

                    for Child_Key, Child_Value in Dendogram_Condensed_Query_Dict[Key].items():

                        if Child_Key != "No Results":
                            Current_Dict = {"name": Child_Key, "url": Child_Value["URL"], "children": []}

                            for Domain, Links in Child_Value["Domain_Links"].items():
                                Current_Inner_Dict = {"name": Domain, "url": url_for("results_filtered") + f"?Result+ID=&Task+ID=&Title=&Plugin=&Status=&Domain={Domain}&Link=&Created+At=&Updated+At=&Result+Type={Child_Key}&setfilter=Set+Filter", "children": []}

                                for Link in Links:
                                    Current_Inner_Dict["children"].append({"name": Link, "url": url_for("results_filtered") + f"?Result+ID=&Task+ID=&Title=&Plugin=&Status=&Domain={Domain}&Link={Link}&Created+At=&Updated+At=&Result+Type={Child_Key}&setfilter=Set+Filter"})

                                Current_Dict["children"].append(Current_Inner_Dict)

                            Child_List.append(Current_Dict)

                        else:
                            Child_List.append({"name": Child_Key, "children": [{"name": "No Domains", "children": [{"name": "No Links"}]}]})

                    URL = url_for("tasks_filtered") + f"?Task+ID=&Query={Key}&Plugin=&Description=&Frequency=&Task+Limit=&Status=&Created+At=&Updated+At=&setfilter=Set+Filter"
                    Dendogram_Data["children"].append({"name": Key, "url": URL, "children": Child_List})

                Dendogram_Data = Common.JSON_Handler(Dendogram_Data).Dump_JSON(Indentation=0)

                for Finding_Type in Finding_Types:
                    Cursor.execute(PSQL_Select_Query, ("Open", Finding_Type,))
                    current_open_results = Cursor.fetchall()
                    open_values.append([current_open_results[0][0]])
                    Cursor.execute(PSQL_Select_Query, ("Closed", Finding_Type,))
                    current_closed_results = Cursor.fetchall()
                    closed_values.append([current_closed_results[0][0]])
                    Cursor.execute(PSQL_Select_Query, ("Reviewing", Finding_Type,))
                    current_mixed_results = Cursor.fetchall()
                    mixed_values.append([current_mixed_results[0][0]])

                if all(open_item == [0] for open_item in open_values):
                    Use_Open: bool = bool()

                if all(closed_item == [0] for closed_item in closed_values):
                    Use_Closed: bool = bool()

                if all(mixed_item == [0] for mixed_item in mixed_values):
                    Use_Mixed: bool = bool()

                return render_template('dashboard.html', resultsdash=True, is_admin=session.get('is_admin'), username=session.get('user'), open_set=[open_values, labels, colors], closed_set=[closed_values, labels, colors], mixed_set=[mixed_values, labels, colors], Use_Open=Use_Open, Use_Closed=Use_Closed, Use_Mixed=Use_Mixed, refreshrate=session.get('dashboard-refresh'), version=Version, Dendogram_Data=Dendogram_Data, Review_Results=Review_Results, Closed_Results=Closed_Results)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('dashboard'))

        @app.route('/dashboard/events', methods=['GET'])
        @admin_requirement
        @login_requirement
        def events_dashboard():

            try:

                def Dict_Setter(User, Dates, Orig_Colors, Index):
                    return {"label": User, "data": Dates, "fill": False, "backgroundColor": Orig_Colors[Index], "borderColor": Orig_Colors[Index], "lineTension": 0.5}

                colors_original = dashboard_colours()
                Dates = Common.Date(Additional_Last_Days=5, Date_Only=True)
                Successful_User_Dates_Count: list = list()
                Unsuccessful_User_Dates_Count: list = list()
                Users_Created_Dates_Count: list = list()
                Cursor.execute('SELECT username FROM users;')
                Current_Users = Cursor.fetchall()
                Current_Index = 2

                for Current_User in Current_Users:
                    Current_User = Current_User[0]
                    Successful_User_Dates: list = list()
                    Unsuccessful_User_Dates: list = list()
                    Users_Created_Dates: list = list()

                    for Date in Dates:
                        SQL_Date = Date + "%"
                        SQL_User_Success: str = "Successful login from " + Current_User + "%"
                        SQL_User_Fail: str = "Failed login attempt for user " + Current_User + "%"
                        SQL_New_User: str = "%" + "user created by " + Current_User + "%"
                        Cursor.execute("SELECT count(*) FROM events WHERE created_at LIKE %s AND description LIKE %s;", (SQL_Date, SQL_User_Success,))
                        Current_Date_Count = Cursor.fetchall()
                        Successful_User_Dates.append(Current_Date_Count[0][0])
                        Cursor.execute("SELECT count(*) FROM events WHERE created_at LIKE %s AND description LIKE %s;", (SQL_Date, SQL_User_Fail,))
                        Current_Date_Count = Cursor.fetchall()
                        Unsuccessful_User_Dates.append(Current_Date_Count[0][0])
                        Cursor.execute("SELECT count(*) FROM events WHERE created_at LIKE %s AND description LIKE %s;", (SQL_Date, SQL_New_User,))
                        Current_Date_Count = Cursor.fetchall()
                        Users_Created_Dates.append(Current_Date_Count[0][0])

                    Successful_User_Dates_Count.append(Dict_Setter(Current_User, Successful_User_Dates, colors_original, Current_Index))
                    Unsuccessful_User_Dates_Count.append(Dict_Setter(Current_User, Unsuccessful_User_Dates, colors_original, Current_Index))
                    Users_Created_Dates_Count.append(Dict_Setter(Current_User, Users_Created_Dates, colors_original, Current_Index))
                    Current_Index += 2

                Successful_User_Dates_Count = Common.JSON_Handler(Successful_User_Dates_Count).Dump_JSON(Indentation=0)
                Unsuccessful_User_Dates_Count = Common.JSON_Handler(Unsuccessful_User_Dates_Count).Dump_JSON(Indentation=0)
                Users_Created_Dates_Count = Common.JSON_Handler(Users_Created_Dates_Count).Dump_JSON(Indentation=0)
                return render_template('dashboard.html', eventsdash=True, is_admin=session.get('is_admin'), username=session.get('user'), successful_line_set=[Dates, Successful_User_Dates_Count], unsuccessful_line_set=[Dates, Unsuccessful_User_Dates_Count], new_users=[Dates, Users_Created_Dates_Count], refreshrate=session.get('dashboard-refresh'), version=Version)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('dashboard'))

        @app.route('/dashboard', methods=['GET'])
        @login_requirement
        def dashboard():

            try:
                return render_template('dashboard.html', is_admin=session.get('is_admin'), username=session.get('user'), version=Version)

            except Exception as e:
                app.logger.error(e)

        @app.route('/dashboard/set-refresh', methods=['POST'])
        @login_requirement
        def dashboard_refresh():

            try:

                if 'setrefresh' in request.form and 'interval' in request.form:
                    approved_refresh_rates = (0, 5, 10, 15, 20, 30, 60)
                    refresh_rate = int(request.form['interval'])

                    if refresh_rate in approved_refresh_rates:
                        session['dashboard-refresh'] = refresh_rate
                        return redirect(url_for('dashboard'))

                    else:
                        return redirect(url_for('dashboard'))

                else:
                    return redirect(url_for('dashboard'))

            except Exception as e:
                app.logger.error(e)

        @app.route('/api/dashboard')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        def api_dashboard():

            try:
                PSQL_Select_Query_1: str = 'SELECT count(*) FROM results WHERE status = %s AND result_type = %s;'
                open_values: dict = dict()
                closed_values: dict = dict()
                mixed_values: dict = dict()

                for Finding_Type in Finding_Types:
                    Cursor.execute(PSQL_Select_Query_1, ("Open", Finding_Type,))
                    current_open_results = Cursor.fetchall()
                    open_values[Finding_Type] = current_open_results[0][0]
                    Cursor.execute(PSQL_Select_Query_1, ("Closed", Finding_Type,))
                    current_closed_results = Cursor.fetchall()
                    closed_values[Finding_Type] = current_closed_results[0][0]
                    Cursor.execute(PSQL_Select_Query_1, ("Reviewing", Finding_Type,))
                    current_mixed_results = Cursor.fetchall()
                    mixed_values[Finding_Type] = current_mixed_results[0][0]

                Cursor.execute("SELECT plugin, COUNT(*) AS counted FROM tasks WHERE plugin IS NOT NULL GROUP BY plugin ORDER BY counted DESC, plugin LIMIT 10;")
                most_common_tasks = Cursor.fetchall()
                data = {"Open Issues": open_values, "Closed Issues": closed_values, "Issues Under Review": mixed_values, "Most Common Tasks": [{}], "Successful Logins in the Last 5 Days": [], "Failed Login Attempts in the Last 5 Days": []}
                
                for mc_task in most_common_tasks:
                    data["Most Common Tasks"][0][mc_task[0]] = mc_task[1]

                Dates = Common.Date(Additional_Last_Days=5, Date_Only=True)
                Cursor.execute('SELECT username FROM users;')
                Current_Users = Cursor.fetchall()
                Current_Index = 2

                for Current_User in Current_Users:
                    Current_User = Current_User[0]
                    Successful_User_Dates: list = list()
                    Unsuccessful_User_Dates: list = list()

                    for Date in Dates:
                        SQL_Date = Date + "%"
                        SQL_User_Success: str = "Successful login from " + Current_User + "%"
                        SQL_User_Fail: str = "Failed login attempt for user " + Current_User + "%"
                        Cursor.execute("SELECT count(*) FROM events WHERE created_at LIKE %s AND description LIKE %s;", (SQL_Date, SQL_User_Success,))
                        Current_Date_Count = Cursor.fetchall()
                        Successful_User_Dates.append({Date: Current_Date_Count[0][0]})
                        Cursor.execute("SELECT count(*) FROM events WHERE created_at LIKE %s AND description LIKE %s;", (SQL_Date, SQL_User_Fail,))
                        Current_Date_Count = Cursor.fetchall()
                        Unsuccessful_User_Dates.append({Date: Current_Date_Count[0][0]})

                    data["Successful Logins in the Last 5 Days"].append({Current_User: {"Dates": Successful_User_Dates}})
                    data["Failed Login Attempts in the Last 5 Days"].append({Current_User: {"Dates": Unsuccessful_User_Dates}})
                    Current_Index += 2

                return jsonify(data), 200

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/logout')
        @login_requirement
        def logout():

            try:
                username = session.get('user')
                session.pop('user', None)
                session.pop('is_admin', False)
                Message = f"Session for user {username} terminated."
                app.logger.warning(Message)
                Create_Event(Message)
                return render_template('index.html', loggedout=True)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('index'))

        @app.route('/events', methods=['GET'])
        @admin_requirement
        @login_requirement
        def events():

            try:
                Cursor.execute("SELECT * FROM events ORDER BY event_id DESC LIMIT 1000")
                events = Cursor.fetchall()
                return render_template('events.html', is_admin=session.get('is_admin'), username=session.get('user'), events=events, Event_Filters=Event_Filters, Event_Filter_Values=list(), Event_Filter_Iterator=list(range(0, len(Event_Filters))))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('events'))

        @app.route('/events/filtered', methods=['GET', 'POST'])
        @admin_requirement
        @login_requirement
        def events_filtered():

            try:
                SQL_Query_Start: str = "SELECT * FROM events WHERE "
                SQL_Query_End: str = " ORDER BY event_id DESC LIMIT 1000"
                SQL_Query_Args: list = list()
                Event_Filter_Values: list = list()

                for Event_Filter in Event_Filters:
                    Current_Filter_Value = str(request.args.get(Event_Filter))

                    if Current_Filter_Value and Current_Filter_Value != str():

                        if "ID" in Event_Filter:
                            Current_Filter_Value = int(Current_Filter_Value)

                        Converted_Filter = Event_Filter.lower().replace(" ", "_")
                    
                        if type(Current_Filter_Value) == int:
                            SQL_Query_Args.append(f"{Converted_Filter} = {str(Current_Filter_Value)}")

                        elif Current_Filter_Value == "*":
                            SQL_Query_Args.append(f"{Converted_Filter} != \'\'")

                        elif type(Current_Filter_Value) == str and Validator(String_to_Check=str(Current_Filter_Value), Safe_Characters=Restricted_Safe_Chars):
                            SQL_Query_Args.append(f"{Converted_Filter} LIKE \'%{Current_Filter_Value}%\'")

                        Event_Filter_Values.append(Current_Filter_Value)
                        
                    else:
                        Event_Filter_Values.append(str())

                if len(SQL_Query_Args) > int():
                    SQL_Query_Args: str = " AND ".join(SQL_Query_Args)
                    SQL_Statement = SQL_Query_Start + SQL_Query_Args + SQL_Query_End
                    Cursor.execute(SQL_Statement)
                    return render_template('events.html', is_admin=session.get('is_admin'), username=session.get('user'), events=Cursor.fetchall(), Event_Filters=Event_Filters, Event_Filter_Values=Event_Filter_Values, Event_Filter_Iterator=list(range(0, len(Event_Filters))))

                else:
                    return redirect(url_for('events'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('events'))

        @app.route('/api/events')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_event_details():

            try:

                if request.method == 'GET':

                    if request.is_json:
                        Content = request.get_json()
                        data: dict = dict()
                        Safe_Content: dict = dict()

                        for Item in Event_Filters:

                            if Item in Content:

                                if Item == "Event ID":

                                    if type(Content[Item]) != int:
                                        return jsonify({"Error": f"The ID provided is not an integer."}), 500

                                    Safe_Content["event_id"] = Content[Item]

                                else:

                                    if not Validator(String_to_Check=str(Content[Item]), Safe_Characters=Restricted_Safe_Chars):
                                        return jsonify({"Error": f"Unsafe value provided."}), 500

                                    if " " in Item:
                                        Safe_Content[Item.lower().replace(" ", "_")] = Content[Item]

                                    else:
                                        Safe_Content[Item.lower()] = Content[Item]

                        if len(Safe_Content) > 1:
                            Select_Query: str = "SELECT * FROM events WHERE "

                            for Item_Key, Item_Value in sorted(Safe_Content.items()):
                                Select_Query += f"{Item_Key} = '{Item_Value}'"

                                if Item_Key != sorted(Safe_Content.keys())[-1]:
                                    Select_Query += " AND "

                                else:
                                    Select_Query += ";"

                            Cursor.execute(Select_Query)

                        elif len(Safe_Content) == 1:
                            Key = list(Safe_Content.keys())[0]
                            Val = list(Safe_Content.values())[0]
                            Select_Query: str = "SELECT * FROM events WHERE "
                            Select_Query += f"{Key} = '{Val}'"
                            Cursor.execute(Select_Query)


                        else:
                            return jsonify({"Error": "No valid fields found in request."}), 500

                        for Event in Cursor.fetchall():
                            data[Event[0]] = [{"Description": Event[1], "Created Timestamp": Event[2]}]

                        return jsonify(data), 200

                    else:
                        data: dict = dict()
                        Cursor.execute('SELECT * FROM events ORDER BY event_id DESC LIMIT 100')

                        for Event in Cursor.fetchall():
                            data[Event[0]] = [{"Description": Event[1], "Created Timestamp": Event[2]}]

                        return jsonify(data), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except:
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/api/endpoints')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        def api_endpoints():

            try:
                Auth_Token = request.headers['Authorization'].replace("Bearer ", "")
                Authentication_Verified = API_verification(Auth_Token)

                if request.method == 'GET':

                    if Authentication_Verified["Admin"]:
                        Auth_Endpoint = {'POST': {"Obtain API Key": {"Endpoint": "/api/auth", "Admin rights required": False, "Fields": {"Username": {"Attributes": {"Required": True, "Type": "String"}}, "Password": {"Attributes": {"Required": True, "Type": "String"}}}}}}
                        Dashboard_Endpoints = {"GET": {"Retrieve dashboard statistics": {"Endpoint": "api/dashboard", "Admin rights required": False}}}
                        Result_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/results", "Admin rights required": False, "Optional Search Filters": {"ID": "Integer", "Associated Task ID": "Integer", "Title": "String", "Plugin": "String", "Domain": "String", "Link": "String", "Screenshot URL": "String", "Status": "String", "Output Files": "String", "Result Type": "String", "Screenshot Requested": "String", "Created At": "String - Timestamp", "Updated At": "String - Timestamp"}}}, "POST": {"Create a new manual result": {"Endpoint": "/api/result/new", "Admin rights required": True, "Fields": {"Name": {"Attributes": {"Required": True, "Type": "String"}}, "URL": {"Attributes": {"Required": True, "Type": "String"}}, "Type": {"Attributes": {"Required": True, "Type": "String"}}}}, "Delete a result": {"Endpoint": "/api/result/delete/<result_id>", "Admin rights required": True}, "Re-open a result": {"Endpoint": "/api/result/changestatus/open/<result_id>", "Admin rights required": True}, "Label a result as under review": {"Endpoint": "/api/result/changestatus/review/<result_id>", "Admin rights required": True}, "Close a result": {"Endpoint": "/api/result/changestatus/close/<result_id>", "Admin rights required": True}}}
                        Task_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/tasks", "Admin rights required": False, "Optional Search Filters": {"ID": "Integer", "Query": "String", "Plugin": "String", "Description": "String", "Frequency": "String - Cronjob", "Limit": "Integer", "Status": "String", "Created At": "String - Timestamp", "Updated At": "String - Timestamp"}}, "Shows which task apis are configured": {"Endpoint": "/api/tasks/inputs/check", "Admin rights required": True}, "Shows which output options are enabled for tasks to export their results to": {"Endpoint": "/api/tasks/outputs/check", "Admin rights required": True}}, "POST": {"Create a new task": {"Endpoint": "/api/task/new", "Admin rights required": True, "Fields": {"Task Type": {"Required": True, "Type": "String"}, "Query": {"Required": True, "Type": "String"}, "Frequency": {"Required": False, "Type": "String - Cronjob"}, "Description": {"Required": False, "Type": "String"}, "Limit": {"Required": False, "Type": "Integer"}}}, "Edit a task": {"Endpoint": "/api/task/edit/<task_id>", "Admin rights required": True, "Fields": {"Task Type": {"Required": True, "Type": "String"}, "Query": {"Required": True, "Type": "String"}, "Frequency": {"Required": False, "Type": "String - Cronjob"}, "Description": {"Required": False, "Type": "String"}, "Limit": {"Required": False, "Type": "Integer"}}}, "Run a task": {"Endpoint": "/api/task/run/<task_id>", "Admin rights required": True}, "Duplicate a task": {"Endpoint": "/api/task/duplicate/<task_id>", "Admin rights required": True}, "Delete a task": {"Endpoint": "/api/task/delete/<task_id>", "Admin rights required": True}}}
                        Event_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/events", "Admin rights required": True, "Optional Search Filters": {"ID": "Integer", "Description": "String", "Created At": "String - Timestamp"}}}}
                        Account_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/accounts", "Admin rights required": True, "Optional Search Filters": {"ID": "Integer", "Username": "String", "Blocked": "Boolean", "Administrative Rights": "Boolean"}}}, "POST": {"Create new account": {"Endpoint": "/api/account/new", "Admin rights required": True, "Fields": {"Username": {"Attributes": {"Required": True, "Type": "String"}}, "Password": {"Attributes": {"Required": True, "Type": "String"}}, "Password Retype": {"Attributes": {"Required": True, "Type": "String"}}}}, "Delete account": {"Endpoint": "/api/account/delete/<account_id>", "Admin rights required": True}, "Disable account": {"Endpoint": "/api/account/disable/<account_id>", "Admin rights required": True}, "Enable account": {"Endpoint": "/api/account/enable/<account_id>", "Admin rights required": True}, "Give account administrative rights": {"Endpoint": "/api/account/promote/<account_id>", "Admin rights required": True}, "Strip account of administrative rights": {"Endpoint": "/api/account/demote/<account_id>", "Admin rights required": True}, "Change any user's password": {"Endpoint": "/api/account/password/change/<account_id>", "Admin rights required": True, "Fields": {"Password": {"Attributes": {"Required": True, "Type": "String"}}, "Password Retype": {"Attributes": {"Required": True, "Type": "String"}}}}}}
                        Identity_Endpoints = {"GET": {"Retrieve identity data": {"Endpoint": "/api/identities", "Admin rights required": True, "Optional Search Filters": {"Identity ID": "Integer", "Firstname": "String", "Middlename": "String", "Surname": "String", "Fullname": "String", "Username": "String", "Email": "String", "Phone": "String"}}, "POST": {"Create new identity": {"Endpoint": "/api/identity/new", "Admin rights required": True, "Fields": {"First": {"Attributes": {"Required": True, "Type": "String"}}, "Middle": {"Attributes": {"Required": False, "Type": "String"}}, "Surname": {"Attributes": {"Required": True, "Type": "String"}}, "Username": {"Attributes": {"Required": False, "Type": "String"}}, "Email": {"Attributes": {"Required": True, "Type": "String"}}, "Phone": {"Attributes": {"Required": True, "Type": "String"}}}}, "Edit identity": {"Endpoint": "/api/identity/edit/<identity_id>", "Admin rights required": True, "Fields": {"First": {"Attributes": {"Required": True, "Type": "String"}}, "Middle": {"Attributes": {"Required": False, "Type": "String"}}, "Surname": {"Attributes": {"Required": True, "Type": "String"}}, "Username": {"Attributes": {"Required": False, "Type": "String"}}, "Email": {"Attributes": {"Required": True, "Type": "String"}}, "Phone": {"Attributes": {"Required": True, "Type": "String"}}}}, "Delete identity": {"Endpoint": "/api/identity/delete/<identity_id>", "Admin rights required": True}}}}
                        Settings_Endpoints = {'GET': {'Retrieve configuration data': {'Endpoint': '/api/settings/configurations/<type_of_configuration>', 'Admin rights required': True}}, 'POST': {'Update configuration': {'Endpoint': '/api/settings/configure/<type_of_configuration>', 'Admin rights required': True, 'Fields': {'object': {'Required': True, 'Type': 'String'}, 'data': {'Required': True, 'Type': 'Dictionary', 'Notes': 'This data depends on the configuration you are updating.'}}}}}
                        return jsonify({"Endpoints": {"API": {"GET": {"Endpoint Checking": "/api/endpoints", "Admin rights required": False}}, "Authentication": Auth_Endpoint, "Dashboard": Dashboard_Endpoints, "Settings": Settings_Endpoints, "Tasks": Task_Endpoints, "Results": Result_Endpoints, "Events": Event_Endpoints, "User Management": Account_Endpoints, "Identity Management": Identity_Endpoints}}), 200

                    else:
                        Auth_Endpoint = {'POST': {"Obtain API Key": {"Endpoint": "/api/auth", "Fields": {"Username": {"Attributes": {"Required": True, "Type": "String"}}, "Password": {"Attributes": {"Required": True, "Type": "String"}}}}}}
                        Dashboard_Endpoints = {"GET": {"Retrieve dashboard statistics": "api/dashboard"}}
                        Result_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/results", "Optional Search Filters": {"ID": "Integer", "Associated Task ID": "Integer", "Title": "String", "Plugin": "String", "Domain": "String", "Link": "String", "Screenshot URL": "String", "Status": "String", "Output Files": "String", "Result Type": "String", "Screenshot Requested": "String", "Created At": "String - Timestamp", "Updated At": "String - Timestamp"}}}}
                        Task_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/tasks", "Optional Search Filters": {"ID": "Integer", "Query": "String", "Plugin": "String", "Description": "String", "Frequency": "String - Cronjob", "Limit": "Integer", "Status": "String", "Created At": "String - Timestamp", "Updated At": "String - Timestamp"}}}}
                        Event_Endpoints = {"GET": {"Retrieve account data": {"Endpoint": "/api/events", "Optional Search Filters": {"ID": "Integer", "Description": "String", "Created At": "String - Timestamp"}}}}
                        return jsonify({"Endpoints": {"API": {"GET": {"Endpoint Checking": "/api/endpoints"}}, "Authentication": Auth_Endpoint, "Dashboard": Dashboard_Endpoints, "Tasks": Task_Endpoints, "Results": Result_Endpoints, "Events": Event_Endpoints}}), 200
                                   
                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except:
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks', methods=['GET', 'POST'])
        @login_requirement
        def tasks():

            try:
                Task_API_Check = session.get('task_api_check')
                Task_Error = session.get('task_error')
                session['task_form_step']: int = int()
                session['task_form_type']: str = str()
                session['task_frequency']: str = str()
                session['task_description']: str = str()
                session['task_limit']: int = int()
                session['task_query']: str = str()
                session['task_id']: int = int()
                session['task_error'] = None
                session['task_api_check'] = None
                Cursor.execute("SELECT * FROM tasks ORDER BY task_id DESC LIMIT 1000")
                task_results = Cursor.fetchall()
                return render_template('tasks.html', username=session.get('user'), form_step=session.get('task_form_step'), is_admin=session.get('is_admin'), results=task_results, Task_Filters=Task_Filters, Task_Filter_Values=list(), Task_Filter_Iterator=list(range(0, len(Task_Filters))), api_check=Task_API_Check, error=Task_Error)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/tasks/filtered', methods=['GET', 'POST'])
        @login_requirement
        def tasks_filtered():

            try:
                session['task_form_step']: int = int()
                session['task_form_type']: str = str()
                session['task_frequency']: str = str()
                session['task_description']: str = str()
                session['task_limit']: int = int()
                session['task_query']: str = str()
                session['task_id']: int = int()
                session['task_error'] = None
                session['task_api_check'] = None
                SQL_Query_Start: str = "SELECT * FROM tasks WHERE "
                SQL_Query_End: str = " ORDER BY task_id DESC LIMIT 1000"
                SQL_Query_Args: list = list()
                Task_Filter_Values: list = list()
            
                for Task_Filter in Task_Filters:
                    Current_Filter_Value = str(request.args.get(Task_Filter))

                    if Current_Filter_Value and Current_Filter_Value != str():

                        if "ID" in Task_Filter:
                            Current_Filter_Value = int(Current_Filter_Value)

                        Converted_Filter = Task_Filter.lower().replace(" ", "_")
                    
                        if type(Current_Filter_Value) == int:
                            SQL_Query_Args.append(f"{Converted_Filter} = {str(Current_Filter_Value)}")

                        elif (type(Current_Filter_Value) == str and Validator(String_to_Check=str(Current_Filter_Value), Safe_Characters=Standard_Safe_Chars)):
                            
                            if Current_Filter_Value == "*":
                                SQL_Query_Args.append(f"{Converted_Filter} != \'\'")

                            else:
                                SQL_Query_Args.append(f"{Converted_Filter} LIKE \'%{Current_Filter_Value}%\'")
                        
                        Task_Filter_Values.append(Current_Filter_Value)

                    else:
                        Task_Filter_Values.append(str())

                if len(SQL_Query_Args) > int():
                    SQL_Query_Args: str = " AND ".join(SQL_Query_Args)
                    SQL_Statement = SQL_Query_Start + SQL_Query_Args + SQL_Query_End
                    Cursor.execute(SQL_Statement)
                    return render_template('tasks.html', username=session.get('user'), form_step=session.get('task_form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), Task_Filters=Task_Filters, Task_Filter_Values=Task_Filter_Values, Task_Filter_Iterator=list(range(0, len(Task_Filters))))

                else:
                    return redirect(url_for('tasks'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/tasks/plugins/cache/clear', methods=['GET'])
        @login_requirement
        @admin_requirement
        def clear_cache_main():

            try:
                File_Path = os.path.dirname(os.path.realpath('__file__'))
                Output_Directory = os.path.join(File_Path, 'static/protected/output')
                List_of_Cache_Directories = os.listdir(Output_Directory)
                return render_template('clear_cache.html', is_admin=session.get('is_admin'), username=session.get('user'), List_of_Cache_Directories=List_of_Cache_Directories)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/tasks/plugins/cache/clear/<plugin>', methods=['GET', 'POST'])
        @login_requirement
        @admin_requirement
        def clear_cache(plugin):

            try:
                File_Path = os.path.dirname(os.path.realpath('__file__'))
                Output_Directory = os.path.join(File_Path, 'static/protected/output')
                List_of_Cache_Directories = os.listdir(Output_Directory)
                Message: str = "Cache already cleared."
                
                if plugin in List_of_Cache_Directories:
                    Cache_Directory = os.path.join(Output_Directory, plugin)
                    Directory_Files = os.listdir(Cache_Directory)

                    for File in Directory_Files:
                        
                        if Common.Regex_Handler(File, Custom_Regex=".+\-cache\.txt"):
                            os.remove(os.path.join(Cache_Directory, File))
                            Message = f"Cache cleared for plugin {plugin}."

                    return render_template('clear_cache.html', is_admin=session.get('is_admin'), username=session.get('user'), List_of_Cache_Directories=List_of_Cache_Directories, message=Message)
                        
                elif plugin == "*":

                    for Dir in List_of_Cache_Directories:
                        Cache_Directory = os.path.join(Output_Directory, Dir)
                        Directory_Files = os.listdir(Cache_Directory)

                        for File in Directory_Files:
                            
                            if Common.Regex_Handler(File, Custom_Regex=".+\-cache\.txt"):
                                os.remove(os.path.join(Cache_Directory, File))
                                Message: str = "All cache cleared."

                    return render_template('clear_cache.html', is_admin=session.get('is_admin'), username=session.get('user'), List_of_Cache_Directories=List_of_Cache_Directories, message=Message)
                
                else:
                    return render_template('clear_cache.html', is_admin=session.get('is_admin'), username=session.get('user'), List_of_Cache_Directories=List_of_Cache_Directories)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('clear_cache_main'))

        @app.route('/api/task/duplicate/<taskid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_tasks_duplicate(taskid):

            try:

                if request.method == 'POST':
                    dup_id = int(taskid)
                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (dup_id,))
                    result = Cursor.fetchone()

                    if result:
                        Current_Timestamp = Common.Date() # Variable set to create consistency in timestamps across two seperate database queries.
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

                            Message = f"Task ID {str(dup_id)} duplicated."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            return jsonify({"Message": "Successfully duplicated task.", "Provided Task ID": dup_id, "New Task ID": task_id}), 200

                        else:
                            return jsonify({"Error": "Unable to retrieve database value."}), 500

                    else:
                        return jsonify({"Error": f"Unable to find provided task id {str(dup_id)}."}), 500

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks/duplicate/<taskid>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def duplicate_task(taskid):

            try:

                def dup_task(dup_id):
                    dup_id = int(dup_id)
                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (dup_id,))
                    result = Cursor.fetchone()

                    if result:
                        Current_Timestamp = Common.Date() # Variable set to create consistency in timestamps across two seperate database queries.
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

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/task/delete/<taskid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_tasks_delete(taskid):

            try:

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
                    Message = f"Task ID {str(del_id)} deleted."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return jsonify({"Message": f"Successfully deleted task id {str(del_id)}."}), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks/delete/<taskid>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def delete_task(taskid):

            try:

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
                                                   form_step=session.get('task_form_step'),
                                                   is_admin=session.get('is_admin'), results=results,
                                                   error=f"Failed to remove task ID {str(del_id)} from crontab.", Task_Filters=Task_Filters, Task_Filter_Values=list(), Task_Filter_Iterator=list(range(0, len(Task_Filters))))

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

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        # deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>
        @app.route('/api/task/run/<taskid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_tasks_run(taskid):
            global Thread_In_Use

            try:

                if request.method == 'POST':
                    Plugin_ID = int(taskid)
                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (Plugin_ID,))
                    result = Cursor.fetchone()

                    if result[6] == "Running":
                        return jsonify({"Error": "Task is already running."}), 500

                    Plugin = plugin_verifier.Plugin_Verifier(result[2], Plugin_ID, result[1], result[5]).Verify_Plugin(Scrummage_Working_Directory)

                    if not Plugin or not all(Item in Plugin for Item in ["Object", "Search Option", "Function Kwargs"]):
                        return jsonify({"Error": f"The task type {result[2]} has not been configured. Please update its configuration in the config.json file or via the admin settings page."}), 500

                    else:

                        def Task_Runner(Result_Inner, Plugin_ID_Inner):
                            plugin_caller.Plugin_Caller(Result=Result_Inner, Task_ID=Plugin_ID_Inner).Call_Plugin(Scrummage_Working_Directory)

                        def Threaded_Task_Runner():
                            global Thread_In_Use
                            
                            if Thread_In_Use and Thread_In_Use.is_alive():
                                Previous_Thread = Thread_In_Use
                                Thread_In_Use = threading.Thread(target=Task_Runner, args=(result, Plugin_ID))
                                Thread_In_Use.start()
                                Previous_Thread.join()
                                Thread_In_Use.join()

                        if Thread_In_Use and Thread_In_Use.is_alive():
                            threading.Thread(target=Threaded_Task_Runner).start()
                                
                        else:
                            Thread_In_Use = threading.Thread(target=Task_Runner, args=(result, Plugin_ID))
                            Thread_In_Use.start()

                        return jsonify({"Message": f"Successfully executed task id {str(Plugin_ID)}."}), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks/run/<taskid>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def run_task(taskid):
            global Thread_In_Use
            global Scrummage_Working_Directory

            try:
                Plugin_ID = int(taskid)
                Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (Plugin_ID,))
                result = Cursor.fetchone()

                if result[6] == "Running":
                    session["task_error"]: str = "Task is already running."
                    return redirect(url_for('tasks'))

                if result[1] == "[IDENTITIES_DATABASE]":
                    ID_DB_Search_Type = Valid_Plugins[result[2]]["Organisation_Presets"]

                    if ID_DB_Search_Type == "identity_usernames":
                        Cursor.execute("SELECT username FROM org_identities;")
                        ID_DB_Results = Cursor.fetchall()

                    elif ID_DB_Search_Type == "identity_emails":
                        Cursor.execute("SELECT email FROM org_identities;")
                        ID_DB_Results = Cursor.fetchall()

                    elif ID_DB_Search_Type == "identity_phones":
                        Cursor.execute("SELECT phone FROM org_identities;")
                        ID_DB_Results = Cursor.fetchall()

                    Filtered_Data: list = list()

                    for Row in ID_DB_Results:
                        Filtered_Data.append(Row[0])

                    Query: str = ", ".join(Filtered_Data)

                else:
                    Query = None

                Plugin = plugin_verifier.Plugin_Verifier(result[2], Plugin_ID, result[1], result[5]).Verify_Plugin(Scrummage_Working_Directory)

                if not Plugin or not (isinstance(Plugin, dict) and all(Item in Plugin for Item in ("Object", "Search Option", "Function Kwargs"))):
                    session["task_api_check"]: str = "Failed"
                    return redirect(url_for('tasks'))

                else:

                    def Task_Runner(Result_Inner, Plugin_ID_Inner, Inner_Query):
                        plugin_caller.Plugin_Caller(Result=Result_Inner, Task_ID=Plugin_ID_Inner, Custom_Query=Inner_Query).Call_Plugin(Scrummage_Working_Directory)

                    def Threaded_Task_Runner():
                        global Thread_In_Use

                        if Thread_In_Use and Thread_In_Use.is_alive():
                            Previous_Thread = Thread_In_Use
                            Thread_In_Use = threading.Thread(target=Task_Runner, args=(result, Plugin_ID, Query))
                            Thread_In_Use.start()
                            Previous_Thread.join()
                            Thread_In_Use.join()

                    if Thread_In_Use and Thread_In_Use.is_alive():
                        threading.Thread(target=Threaded_Task_Runner).start()
                            
                    else:
                        Thread_In_Use = threading.Thread(target=Task_Runner, args=(result, Plugin_ID, Query))
                        Thread_In_Use.start()
                    
                    session["task_api_check"]: str = "Passed"
                    time.sleep(1.5)
                    return redirect(url_for('tasks'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/task/new')
        @csrf.exempt
        @api_auth_requirement
        @api_admin_requirement
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_tasks_new():

            try:
                Safe_Chars: list = Restricted_Safe_Chars.copy()

                if request.method == 'POST':

                    if request.is_json:
                        Content = request.get_json()

                        if all(Items in Content for Items in ["Task Type", "Query"]):
                            Frequency: str = str()
                            Description: str = str()
                            Limit: int = int()
                            
                            if Content['Task Type'] not in Valid_Plugins.keys():
                                return jsonify({"Error": "The task type is not a valid option."}), 500

                            Plugin_in_List = Valid_Plugins[Content['Task Type']]

                            if type(Plugin_in_List.get('Safe_Characters')) == list and "Safe_Characters" in Plugin_in_List:
                                Safe_Chars.extend(Plugin_in_List["Safe_Characters"])

                            if (Validator(String_to_Check=str(Content['Query']), Safe_Characters=Safe_Chars) and Content['Query'] != "[IDENTITIES_DATABASE]"):
                                return jsonify({"Error": "Potentially dangerous query identified. Please ensure your query does not contain any bad characters."}), 500

                            if Valid_Plugins[Content['Task Type']].get("Organisation_Presets") and not Common.Regex_Handler(Content['Query'], Type=Org_Preset_to_Regex_Mapping[Valid_Plugins[Content['Task Type']]["Organisation_Presets"]]):
                                Type = Org_Preset_to_Regex_Mapping[Valid_Plugins[Content['Task Type']]["Organisation_Presets"]].lower()
                                return jsonify({"Error": f"The query provided was invalid for the type of query expected. Please enter a valid {Type}."}), 500

                            if 'Frequency' in Content:
                                task_frequency_regex = Common.Regex_Handler(Content('frequency'), Type="Cron")

                                if task_frequency_regex:
                                    Updated_Cron: list = list()

                                    for Group in range(1, 6):
                                        Items = {1: [0, 59], 2: [0, 23], 3: [1, 31], 4: [1, 12], 5: [0, 6]}
                                        Regex_Group = task_frequency_regex.group(Group)
                                        
                                        if "," in Regex_Group:
                                            Item = Common.Filter(Regex_Group.split(","), Items[Group][0], Items[Group][1])
                                            Updated_Cron.append(",".join(Item))

                                        else:
                                            Updated_Cron.append(Regex_Group)

                                    Frequency: str = " ".join(Updated_Cron)
                                        
                                else:
                                    return jsonify({"Error": "Invalid frequency, please provide a valid frequency in the same way you would set up a cronjob or leave the field blank. i.e. \"* */5 * * *\""}), 500

                            if 'Description' in Content:
                                Description = html.escape(Content['Description'])

                            if 'Limit' in Content and Valid_Plugins[Content['Task Type']]["Requires_Limit"]:
                                
                                try:
                                    Limit = int(Content['Limit'])

                                except:
                                    return jsonify({"Error": "Failed to convert limit to an integer."}), 500

                            Current_Timestamp = Common.Date()  # Variable set as it is needed for two different functions and needs to be consistent.
                            Cursor.execute('INSERT INTO tasks (query, plugin, description, frequency, task_limit, status, created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)', (
                            Content["Query"], Content["Task Type"], Description, Frequency, str(Limit), "Stopped", Current_Timestamp, Current_Timestamp,))
                            Connection.commit()
                            time.sleep(1)
                            Cursor.execute("SELECT * FROM tasks WHERE query = %s AND plugin = %s AND description = %s AND frequency = %s AND task_limit = %s AND status = %s AND created_at = %s AND updated_at = %s;", (
                            Content["Query"], Content["Task Type"], Description, Frequency, str(Limit), "Stopped", str(Current_Timestamp), str(Current_Timestamp),))
                            result = Cursor.fetchone()
                            current_task_id = result[0]

                            if Frequency != str():
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

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks/new', methods=['POST', 'GET'])
        @login_requirement
        @admin_requirement
        def new_task():

            try:
                Safe_Chars: list = Restricted_Safe_Chars.copy()
                Suggestion = Common.Configuration(Core=True).Load_Configuration(Object="organisation", Details_to_Load=["name", "website", "domain", "subdomains"])

                if session.get('task_form_step') == 0 or request.method == "GET":
                    session['task_form_step'] = 1
                    return render_template('tasks.html', username=session.get('user'),
                                            form_type=session.get('task_form_type'),
                                            is_admin=session.get('is_admin'), form_step=session.get('task_form_step'),
                                            new_task=True, suggestion=Suggestion,
                                            Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins())

                elif session.get('task_form_step') == 1:
                    time.sleep(1)

                    if request.form.get('tasktype') not in Valid_Plugins.keys():
                        return render_template('tasks.html', username=session.get('user'),
                                                form_type=session.get('task_form_type'),
                                                new_task=True, Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                is_admin=session.get('is_admin'), suggestion=Suggestion,
                                                form_step=session.get('task_form_step'),
                                                error="Please choose a valid task from the provided list for the Task Type field.")

                    if request.form.get('frequency') != str():
                        session['task_frequency'] = request.form['frequency']
                        task_frequency_regex = Common.Regex_Handler(session.get('task_frequency'), Type="Cron")

                        if task_frequency_regex:
                            Updated_Cron: list = list()

                            for Group in range(1, 6):
                                Items = {1: [0, 59], 2: [0, 23], 3: [1, 31], 4: [1, 12], 5: [0, 6]}
                                Regex_Group = task_frequency_regex.group(Group)
                                
                                if "," in Regex_Group:
                                    Item = Common.Filter(Regex_Group.split(","), Items[Group][0], Items[Group][1])
                                    Updated_Cron.append(",".join(Item))

                                else:
                                    Updated_Cron.append(Regex_Group)

                            session['task_frequency']: str = " ".join(Updated_Cron)
                                
                        else:
                            return render_template('tasks.html', username=session.get('user'),
                                                    form_step=session.get('task_form_step'),
                                                    form_type=session.get('task_form_type'),
                                                    is_admin=session.get('is_admin'), new_task=True, suggestion=Suggestion,
                                                    Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                    error="Invalid frequency, please provide a valid frequency in the same way you would set up a cronjob or leave the field blank. i.e. \"* */5 * * *\"")

                    if 'description' in request.form:
                        session['task_description'] = html.escape(request.form['description'])

                    Plugin_in_List = Valid_Plugins[request.form.get('tasktype')]

                    if type(Plugin_in_List.get('Safe_Characters')) == list and "Safe_Characters" in Plugin_in_List:
                        Safe_Chars.extend(Plugin_in_List['Safe_Characters'])

                    session['task_form_type'] = request.form['tasktype']                     

                    if 'query' in request.form:

                        if request.form['query']:
                            Frequency_Error: str = str()
                            session['task_query'] = request.form['query']
                            Current_Query_List = General.Convert_to_List(session['task_query'])

                            for Current_Query in Current_Query_List:

                                if (Valid_Plugins[session['task_form_type']].get("Organisation_Presets") and Common.Regex_Handler(Current_Query, Type=Org_Preset_to_Regex_Mapping[Valid_Plugins[session['task_form_type']]["Organisation_Presets"]])) or not Valid_Plugins[session['task_form_type']].get("Organisation_Presets"):

                                    if request.form.get('limit') and Valid_Plugins[session.get('task_form_type')]["Requires_Limit"]:

                                        if not Validator(String_to_Check=str(Current_Query), Safe_Characters=Safe_Chars) and not (Current_Query == session['task_query'] and Current_Query == "[IDENTITIES_DATABASE]"):
                                            return render_template('tasks.html', username=session.get('user'),
                                                                        form_type=session.get('task_form_type'),
                                                                        form_step=session.get('task_form_step'), suggestion=Suggestion,
                                                                        Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                                        is_admin=session.get('is_admin'), new_task=True, error="Invalid query specified, your query contains unsupported special characters.")

                                        try:
                                            session['task_limit'] = int(request.form['limit'])

                                        except:
                                            return render_template('tasks.html', username=session.get('user'),
                                                                    form_type=session.get('task_form_type'),
                                                                    form_step=session.get('task_form_step'), suggestion=Suggestion,
                                                                    Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                                    is_admin=session.get('is_admin'), new_task=True, error="Invalid limit specified, please provide a valid limit represented by a number.")

                                    else:

                                        if not Validator(String_to_Check=str(Current_Query), Safe_Characters=Safe_Chars) and not (Current_Query == session['task_query'] and Current_Query == "[IDENTITIES_DATABASE]"):
                                            return render_template('tasks.html', username=session.get('user'),
                                                                        form_type=session.get('task_form_type'),
                                                                        form_step=session.get('task_form_step'), new_task=True,
                                                                        is_admin=session.get('is_admin'), suggestion=Suggestion,
                                                                        Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                                        error="Invalid query specified, your query contains unsupported special characters.")

                                else:
                                    Type = Org_Preset_to_Regex_Mapping[Valid_Plugins[session['task_form_type']]["Organisation_Presets"]].lower()
                                    return render_template('tasks.html', username=session.get('user'),
                                                                        form_type=session.get('task_form_type'),
                                                                        form_step=session.get('task_form_step'), new_task=True,
                                                                        is_admin=session.get('is_admin'), suggestion=Suggestion,
                                                                        Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                                        error=f"The query provided was invalid for the type of query expected. Please enter a valid {Type}.")

                            Current_Timestamp = Common.Date()
                            Cursor.execute('INSERT INTO tasks (query, plugin, description, frequency, task_limit, status, created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)', (
                            session.get('task_query'), session.get('task_form_type'), session.get('task_description'),
                            session.get('task_frequency'), session.get('task_limit'), "Stopped",
                            Current_Timestamp, Current_Timestamp,))
                            Connection.commit()
                            Message = f"New task created by {session.get('user')}."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            time.sleep(1)

                            if session.get('task_frequency'):
                                Cursor.execute("SELECT * FROM tasks WHERE query = %s AND plugin = %s AND description = %s AND frequency = %s AND task_limit = %s AND status = %s AND created_at = %s AND updated_at = %s;", (
                                session.get('task_query'), session.get('task_form_type'), session.get('task_description'),
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
                                    Frequency_Error = f"Task created but no cronjob was created due to the supplied frequency being invalid, please double check the frequency for task ID {str(current_task_id)} and use the \"Edit\" button to update it in order for the cronjob to be created."

                            session['task_form_step'] = int()
                            Cursor.execute("SELECT * FROM tasks")
                            results = Cursor.fetchall()

                            if Frequency_Error:
                                return render_template('tasks.html', username=session.get('user'), form_type=session.get('task_form_type'),
                                                        form_step=session.get('task_form_step'), Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                        new_task=True, is_admin=session.get('is_admin'), suggestion=Suggestion,
                                                        results=results, error=Frequency_Error)

                            else:
                                return redirect(url_for('tasks'))

                        else:
                            return render_template('tasks.html', username=session.get('user'),
                                                        form_type=session.get('task_form_type'),
                                                        new_task=True, is_admin=session.get('is_admin'), suggestion=Suggestion,
                                                        form_step=session.get('task_form_step'), Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                        error="Please provide a valid query to search for.")

                    else:
                        return render_template('tasks.html', username=session.get('user'),
                                                    form_type=session.get('task_form_type'),
                                                    new_task=True, is_admin=session.get('is_admin'), suggestion=Suggestion,
                                                    form_step=session.get('task_form_step'), Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                    error="Please provide a valid query to search for.")
                    
                else:
                    return redirect(url_for('tasks'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/task/edit/<taskid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_tasks_edit(taskid):

            try:
                Safe_Chars: list = Restricted_Safe_Chars.copy()

                if request.method == 'POST':

                    try:
                        current_task_id = int(taskid)

                    except:
                        return jsonify({"Error": "Failed to convert task id to an integer."}), 500

                    if request.is_json:
                        Content = request.get_json()

                        if all(Items in Content for Items in ["Task Type", "Query"]):
                            Frequency: str = str()
                            Description: str = str()
                            Limit: int = int()
                            
                            if Content['Task Type'] not in Valid_Plugins.keys():
                                return jsonify({"Error": "The task type is not a valid option."}), 500

                            Plugin_in_List = Valid_Plugins[Content['Task Type']]

                            if type(Plugin_in_List.get('Safe_Characters')) == list and "Safe_Characters" in Plugin_in_List:
                                Safe_Chars.extend(Plugin_in_List["Safe_Characters"])

                            if (Validator(String_to_Check=str(Content['Query']), Safe_Characters=Safe_Chars) and Content['Query'] != "[IDENTITIES_DATABASE]"):
                                return jsonify({"Error": "Potentially dangerous query identified. Please ensure your query does not contain any bad characters."}), 500

                            if Valid_Plugins[Content['Task Type']].get("Organisation_Presets") and not Common.Regex_Handler(Content['Query'], Type=Org_Preset_to_Regex_Mapping[Valid_Plugins[Content['Task Type']]["Organisation_Presets"]]):
                                Type = Org_Preset_to_Regex_Mapping[Valid_Plugins[Content['Task Type']]["Organisation_Presets"]].lower()
                                return jsonify({"Error": f"The query provided was invalid for the type of query expected. Please enter a valid {Type}."}), 500

                            if 'Frequency' in Content:
                                task_frequency_regex = Common.Regex_Handler(Content('frequency'), Type="Cron")

                                if task_frequency_regex:
                                    Updated_Cron: list = list()

                                    for Group in range(1, 6):
                                        Items = {1: [0, 59], 2: [0, 23], 3: [1, 31], 4: [1, 12], 5: [0, 6]}
                                        Regex_Group = task_frequency_regex.group(Group)
                                        
                                        if "," in Regex_Group:
                                            Item = Common.Filter(Regex_Group.split(","), Items[Group][0], Items[Group][1])
                                            Updated_Cron.append(",".join(Item))

                                        else:
                                            Updated_Cron.append(Regex_Group)

                                    Frequency: str = " ".join(Updated_Cron)
                                    Update_Cron: bool = bool()
                                    Cursor.execute("SELECT frequency FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                                    result = Cursor.fetchone()
                                    Original_Frequency = result[0]
                                    Cron_Command = f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {current_task_id}'

                                    if Frequency != str() and Frequency != Original_Frequency:
                                        Update_Cron: bool = True

                                    elif Frequency != str() and Frequency == Original_Frequency:
                                        Update_Cron: bool = bool()

                                    elif Frequency == str() and Original_Frequency == str():
                                        Remove_Cron: bool = True

                                    elif Frequency != str() and Original_Frequency == str():
                                        Create_Cron: bool = True

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
                                        
                                else:
                                    return jsonify({"Error": "Invalid frequency, please provide a valid frequency in the same way you would set up a cronjob or leave the field blank. i.e. \"* */5 * * *\""}), 500                                  

                            if 'Description' in Content:
                                Description = html.escape(Content['Description'])

                            if 'Limit' in Content and Valid_Plugins[Content['Task Type']]["Requires_Limit"]:
                                
                                try:
                                    Limit = int(Content['Limit'])

                                except:
                                    return jsonify({"Error": "Failed to convert limit to an integer."}), 500

                            Current_Timestamp = Common.Date()  # Variable set as it is needed for two different functions and needs to be consistent.
                            Cursor.execute('UPDATE tasks SET query = %s, plugin = %s, description = %s, frequency = %s, task_limit = %s, updated_at = %s WHERE task_id = %s', (Content["Query"], Content["Task Type"], Description, Frequency, str(Limit), Current_Timestamp, current_task_id,))
                            Connection.commit()
                            return jsonify({"Message": f"Successfully updated task id {str(current_task_id)}"}), 200

                        else:
                            return jsonify({"Error": "Missing one or more required fields."}), 500

                    else:
                        return jsonify({"Error": "Request is not in JSON format."}), 500

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/tasks/edit/<taskid>', methods=['POST', 'GET'])
        @login_requirement
        @admin_requirement
        def edit_task(taskid):

            try:
                Safe_Chars: list = Restricted_Safe_Chars.copy()
                Suggestion = Common.Configuration(Core=True).Load_Configuration(Object="organisation", Details_to_Load=["name", "website", "domain", "subdomains"])

                if session.get('task_form_step') == int() or request.method == "GET":

                    session['task_id'] = int(taskid)
                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                    results = Cursor.fetchone()

                    if results:
                        session['task_form_step'] = 1
                        return render_template('tasks.html', username=session.get('user'), form_step=session.get('task_form_step'), edit_task=True, suggestion=Suggestion, Valid_Plugins=list(Valid_Plugins.keys()), is_admin=session.get('is_admin'), results=results, Plugins_without_Limit=No_Limit_Plugins(), Without_Limit=(not Valid_Plugins[results[2]]["Requires_Limit"]),)

                    else:
                        return redirect(url_for('tasks'))

                elif session.get('task_form_step') == 1:
                    time.sleep(1)
                    Cursor.execute("SELECT * FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                    results = Cursor.fetchone()

                    if request.form.get('tasktype') and request.form.get('tasktype') in Valid_Plugins.keys():
                        
                        if request.form.get('frequency') != str():
                            session['task_frequency'] = request.form['frequency']
                            task_frequency_regex = Common.Regex_Handler(session.get('task_frequency'), Type="Cron")

                            if task_frequency_regex:
                                Updated_Cron: list = list()

                                for Group in range(1, 6):
                                    Items: dict = {1: [0, 59], 2: [0, 23], 3: [1, 31], 4: [1, 12], 5: [0, 6]}
                                    Regex_Group = task_frequency_regex.group(Group)
                                    
                                    if "," in Regex_Group:
                                        Item = Common.Filter(Regex_Group.split(","), Items[Group][0], Items[Group][1])
                                        Updated_Cron.append(",".join(Item))

                                    else:
                                        Updated_Cron.append(Regex_Group)

                                session['task_frequency']: str = " ".join(Updated_Cron)
                                    
                            else:
                                return render_template('tasks.html', username=session.get('user'),
                                                        form_step=session.get('task_form_step'),
                                                        form_type=session.get('task_form_type'), results=results, Without_Limit=(not Valid_Plugins[results[2]]["Requires_Limit"]), 
                                                        is_admin=session.get('is_admin'), edit_task=True, suggestion=Suggestion,
                                                        Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                        error="Invalid frequency, please provide a valid frequency in the same way you would set up a cronjob or leave the field blank. i.e. \"* */5 * * *\"")

                        if 'description' in request.form:
                            session['task_description'] = html.escape(request.form['description'])

                        Plugin_in_List = Valid_Plugins[request.form.get('tasktype')]

                        if type(Plugin_in_List.get('Safe_Characters')) == list and "Safe_Characters" in Plugin_in_List:
                            Safe_Chars.extend(Plugin_in_List["Safe_Characters"])

                        session['task_form_type'] = request.form['tasktype']

                    else:
                        return render_template('tasks.html', username=session.get('user'),
                                               form_step=session.get('task_form_step'),
                                               edit_task=True, Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(), Without_Limit=(not Valid_Plugins[results[2]]["Requires_Limit"]),
                                               is_admin=session.get('is_admin'), results=results, suggestion=Suggestion,
                                               error="Invalid task type, please select an option from the provided list for the Task Type field.")

                    if 'query' in request.form:

                        if request.form['query']:
                            Frequency_Error: str = str()
                            session['task_query'] = request.form['query']
                            Current_Query_List = General.Convert_to_List(session['task_query'])

                            for Current_Query in Current_Query_List:

                                if (Valid_Plugins[session['task_form_type']].get("Organisation_Presets") and Common.Regex_Handler(Current_Query, Type=Org_Preset_to_Regex_Mapping[Valid_Plugins[session['task_form_type']]["Organisation_Presets"]])) or not Valid_Plugins[session['task_form_type']].get("Organisation_Presets"):

                                    if request.form.get('limit') and Valid_Plugins[session.get('task_form_type')]["Requires_Limit"]:

                                        if not Validator(String_to_Check=str(Current_Query), Safe_Characters=Safe_Chars) and not (Current_Query == session['task_query'] and Current_Query == "[IDENTITIES_DATABASE]"):
                                            return render_template('tasks.html', username=session.get('user'),
                                                                    form_step=session.get('task_form_step'), edit_task=True, Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(), Without_Limit=(not Valid_Plugins[results[2]]["Requires_Limit"]),
                                                                    results=results, is_admin=session.get('is_admin'), suggestion=Suggestion,
                                                                    form_type=session.get('task_form_type'),
                                                                    error="Invalid query specified, your query contains unsupported special characters.")

                                        try:
                                            session['task_limit'] = int(request.form['limit'])

                                        except:
                                            return render_template('tasks.html', username=session.get('user'),
                                                                form_step=session.get('task_form_step'), edit_task=True,
                                                                form_type=session.get('task_form_type'), suggestion=Suggestion,
                                                                Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(), Without_Limit=(not Valid_Plugins[results[2]]["Requires_Limit"]), results=results,
                                                                is_admin=session.get('is_admin'),
                                                                error="Invalid limit specified, please provide a valid limit represented by a number.")

                                    else:

                                        if not Validator(String_to_Check=str(Current_Query), Safe_Characters=Safe_Chars) and not (Current_Query == session['task_query'] and Current_Query == "[IDENTITIES_DATABASE]"):
                                            return render_template('tasks.html', username=session.get('user'),
                                                                        form_type=session.get('task_form_type'), suggestion=Suggestion,
                                                                        form_step=session.get('task_form_step'), edit_task=True,
                                                                        is_admin=session.get('is_admin'),
                                                                        Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(), Without_Limit=(not Valid_Plugins[results[2]]["Requires_Limit"]), results=results,
                                                                        error="Invalid query specified, your query contains unsupported special characters.")

                                else:
                                    Type = Org_Preset_to_Regex_Mapping[Valid_Plugins[session['task_form_type']]["Organisation_Presets"]].lower()
                                    return render_template('tasks.html', username=session.get('user'),
                                                                        form_type=session.get('task_form_type'), suggestion=Suggestion,
                                                                        form_step=session.get('task_form_step'), edit_task=True,
                                                                        is_admin=session.get('is_admin'),
                                                                        Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(), Without_Limit=(not Valid_Plugins[results[2]]["Requires_Limit"]), results=results,
                                                                        error=f"The query provided was invalid for the type of query expected. Please enter a valid {Type}.")

                            Update_Cron: bool = bool()

                            if session.get('task_frequency') != str():
                                Cursor.execute("SELECT frequency FROM tasks WHERE task_id = %s;", (session.get('task_id'),))
                                result = Cursor.fetchone()
                                original_frequency = result[0]

                                if not original_frequency == session.get('task_frequency'):
                                    Update_Cron: bool = True

                            else:

                                if results[4] != str():

                                    try:
                                        my_cron = CronTab(user=getpass.getuser())

                                        for job in my_cron:

                                            if job.command == f'/usr/bin/python3 {File_Path}/plugin_caller.py -t {str(session.get("task_id"))}':
                                                my_cron.remove(job)
                                                my_cron.write()

                                    except:
                                        return render_template('tasks.html', username=session.get('user'),
                                                               form_type=session.get('task_form_type'), suggestion=Suggestion,
                                                               form_step=session.get('task_form_step'), Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                               Without_Limit=(not Valid_Plugins[results[2]]["Requires_Limit"]), is_admin=session.get('is_admin'), edit_task=True,
                                                               error="Failed to update cron job.")

                            Cursor.execute('UPDATE tasks SET query = %s, plugin = %s, description = %s, frequency = %s, task_limit = %s, updated_at = %s WHERE task_id = %s', (
                            session.get('task_query'), session.get('task_form_type'), session.get('task_description'),
                            session.get('task_frequency'), session.get('task_limit'), Common.Date(),
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
                                    Frequency_Error = f"Task updated but no cronjob was added, and any valid original cron jobs for this task have been removed due to an invalid frequency being supplied, please double check the frequency for task ID {str(current_task_id)} and use the \"Edit\" button to edit the frequency to create a cronjob."

                            Message = f"Task ID {str(session.get('task_id'))} updated by {session.get('user')}."
                            app.logger.warning(Message)
                            Create_Event(Message)
                            session['task_form_step'] = int()
                            Cursor.execute("SELECT * FROM tasks")
                            results = Cursor.fetchall()

                            if Frequency_Error:
                                return render_template('tasks.html', username=session.get('user'),
                                                       form_step=session.get('task_form_step'), Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(),
                                                       Without_Limit=(not Valid_Plugins[results[2]]["Requires_Limit"]), edit_task=True, is_admin=session.get('is_admin'),
                                                       results=results, error=Frequency_Error, suggestion=Suggestion)

                            else:
                                return redirect(url_for('tasks'))

                        else:
                            return render_template('tasks.html', username=session.get('user'),
                                                       form_step=session.get('task_form_step'), edit_task=True, suggestion=Suggestion,
                                                       Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(), is_admin=session.get('is_admin'),
                                                       Without_Limit=(not Valid_Plugins[results[2]]["Requires_Limit"]), results=results,
                                                       error="Please provide a valid query to search for.")

                    else:
                        return render_template('tasks.html', username=session.get('user'),
                                                   form_step=session.get('task_form_step'), edit_task=True, suggestion=Suggestion,
                                                   Valid_Plugins=list(Valid_Plugins.keys()), Plugins_without_Limit=No_Limit_Plugins(), is_admin=session.get('is_admin'),
                                                   Without_Limit=(not Valid_Plugins[results[2]]["Requires_Limit"]), results=results,
                                                   error="Please provide a valid query to search for.")

                else:
                    return redirect(url_for('tasks'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('tasks'))

        @app.route('/api/tasks')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        def api_task_details():

            try:

                if request.method == 'GET':

                    if request.is_json:
                        Content = request.get_json()
                        data: dict = dict()
                        Safe_Content: dict = dict()

                        for Item in Task_Filters:

                            if Item in Content:

                                if Validator(String_to_Check=str(Content[Item]), Safe_Characters=Standard_Safe_Chars):
                                    return jsonify({"Error": f"Bad characters detected in the {Item} field."}), 500

                                if Item == "Task ID":

                                    if type(Content[Item]) != int:
                                        return jsonify({"Error": f"The ID provided is not an integer."}), 500

                                    else:
                                        Safe_Content["task_id"] = Content[Item]

                                elif Item == "Task Limit":
                                    Safe_Content["task_limit"] = Content[Item]

                                elif Item == "Created At":
                                    Safe_Content["created_at"] = Content[Item]

                                elif Item == "Updated At":
                                    Safe_Content["updated_at"] = Content[Item]

                                else:
                                    Safe_Content[Item.lower()] = Content[Item]

                        if len(Safe_Content) > 1:
                            Select_Query: str = "SELECT * FROM tasks WHERE "

                            for Item_Key, Item_Value in sorted(Safe_Content.items()):
                                Select_Query += f"{Item_Key} = '{Item_Value}'"

                                if Item_Key != sorted(Safe_Content.keys())[-1]:
                                    Select_Query += " AND "

                                else:
                                    Select_Query += ";"

                            Cursor.execute(Select_Query)

                        elif len(Safe_Content) == 1:
                            Key = list(Safe_Content.keys())[0]
                            Val = list(Safe_Content.values())[0]
                            Select_Query: str = "SELECT * FROM tasks WHERE "
                            Select_Query += f"{Key} = '{Val}'"
                            Cursor.execute(Select_Query)

                        else:
                            return jsonify({"Error": "No valid fields found in request."}), 500

                        for Task in Cursor.fetchall():
                            data[Task[0]] = {"Query": Task[1], "Plugin": Task[2], "Description": Task[3], "Frequency": Task[4], "Limit": int(Task[5]), "Status": Task[6], "Created Timestamp": Task[7], "Last Updated Timestamp": Task[8]}

                        return jsonify(data), 200

                    else:
                        data: dict = dict()
                        Cursor.execute('SELECT * FROM tasks ORDER BY task_id DESC LIMIT 1000')

                        for Task in Cursor.fetchall():
                            data[Task[0]] = {"Query": Task[1], "Plugin": Task[2], "Description": Task[3], "Frequency": Task[4], "Limit": int(Task[5]), "Status": Task[6], "Created Timestamp": Task[7], "Last Updated Timestamp": Task[8]}

                        return jsonify(data), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/results/upload', methods=['POST', 'GET'])
        @login_requirement
        @admin_requirement
        def bulk_result_upload():

            try:

                if session.get('results_form_step') == 0 or request.method == "GET":
                    session['results_form_step'] = 1
                    session['results_form_type']: str = "bulk"
                    return render_template('results.html', username=session.get('user'), form_type=session.get("results_form_type"), form_step=session.get('results_form_step'), is_admin=session.get('is_admin'), Finding_Types=Finding_Types)

                elif session.get('results_form_step') == 1:
                    time.sleep(1)

                    if request.form.get("bulk_results"):
                        Iterator = 1
                        Records_to_Insert: list = list()

                        for Result_Row in request.form["bulk_results"].split("\r\n"):
                            Attributes = Result_Row.split(",")
                            Final_List: list = list()

                            if len(Attributes) == 3:
                                Attr_Iterator: int = int()

                                for Attribute in Attributes:

                                    if Attr_Iterator not in [1, 2] and any(Attribute.startswith(Bad_Start_Char) for Bad_Start_Char in ["+", "@", "-", "=", " "]):
                                        return render_template('results.html', username=session.get('user'), is_admin=session.get('is_admin'), form_type=session.get("results_form_type"), form_step=session.get('results_form_step'), error=f"Please ensure the fields do not contain any bad characters. The offending line is line {str(Iterator)}.")
                                
                                    elif Attr_Iterator == 1:
                                        URL_Regex = Common.Regex_Handler(Attribute, Type="URL")

                                        if URL_Regex:
                                            Final_List.append(URL_Regex.group(3))
                                            Final_List.append(Attribute)

                                        else:
                                            return render_template('results.html', username=session.get('user'), is_admin=session.get('is_admin'), form_type=session.get("results_form_type"), form_step=session.get('results_form_step'), error=f"Please ensure the provided URL is in the correct format. The offending line is line {str(Iterator)}.")
                                
                                    elif Attr_Iterator == 2 and Attribute not in Finding_Types:
                                        return render_template('results.html', username=session.get('user'), is_admin=session.get('is_admin'), form_type=session.get("results_form_type"), form_step=session.get('results_form_step'), error=f"Please ensure the provided finding type is in the approved list. The offending line is line {str(Iterator)}.")

                                    else:

                                        if Attr_Iterator == 0:
                                            Final_List.append(Attribute.capitalize())

                                        elif Attr_Iterator != 1:
                                            Final_List.append(Attribute)

                                    Attr_Iterator += 1

                                Records_to_Insert.append(Final_List)

                            else:
                                return render_template('results.html', username=session.get('user'), is_admin=session.get('is_admin'), form_type=session.get("results_form_type"), form_step=session.get('results_form_step'), error=f"Please ensure none of the lines have missing fields. The offending line is line {str(Iterator)}.")

                            Iterator += 1

                        if len(Records_to_Insert) > int():

                            for Record in Records_to_Insert:
                                Cursor.execute('INSERT INTO results (task_id, title, status, plugin, domain, link, created_at, updated_at, result_type) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)', (0, str(Record[0]), "Open", "Manual Entry", str(Record[1]), str(Record[2]), Common.Date(), Common.Date(), Record[3],))
                        
                        Connection.commit()
                        Message = f"Bulk results uploaded by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)
                        time.sleep(1)
                        return redirect(url_for('results'))

                else:
                    return redirect(url_for('results'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/results/new', methods=['POST', 'GET'])
        @login_requirement
        @admin_requirement
        def new_result():

            try:

                if session.get('results_form_step') == 0 or request.method == "GET":
                    session['results_form_step'] = 1
                    session['results_form_type']: str = "new"
                    return render_template('results.html', username=session.get('user'), form_step=session.get('results_form_step'), form_type=session.get("results_form_type"), is_admin=session.get('is_admin'), Finding_Types=Finding_Types)

                elif session.get('results_form_step') == 1:
                    time.sleep(1)

                    if all(Item in request.form for Item in ['Name', 'URL', 'Type']):

                        if not Validator(String_to_Check=str(request.form['Name']), Safe_Characters=["-", ".", ",", ":"]):
                            return render_template('results.html', username=session.get('user'), form_step=session.get('results_form_step'), form_type=session.get("results_form_type"), is_admin=session.get('is_admin'), Finding_Types=Finding_Types, error="Bad characters identified in the name field, please remove special characters from the name field.")

                        if not request.form['Type'] in Finding_Types:
                            return render_template('results.html', username=session.get('user'), form_step=session.get('results_form_step'), form_type=session.get("results_form_type"), is_admin=session.get('is_admin'), Finding_Types=Finding_Types, error="Result type is invalid.")

                        URL_Regex = Common.Regex_Handler(request.form['URL'], Type="URL")

                        if not URL_Regex:
                            return render_template('results.html', username=session.get('user'), form_step=session.get('results_form_step'), form_type=session.get("results_form_type"), is_admin=session.get('is_admin'), Finding_Types=Finding_Types, error="URL is invalid.")

                        Cursor.execute('INSERT INTO results (task_id, title, status, plugin, domain, link, created_at, updated_at, result_type) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)', (0, str(request.form['Name']), "Open", "Manual Entry", str(URL_Regex.group(3)), str(request.form['URL']), Common.Date(), Common.Date(), request.form['Type'],))
                        Connection.commit()
                        Message = f"New result created by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)
                        return redirect(url_for('results'))

                    else:
                        return render_template('results.html', username=session.get('user'), form_step=session.get('results_form_step'), form_type=session.get("results_form_type"), is_admin=session.get('is_admin'), Finding_Types=Finding_Types, error="Invalid entry/entries, please fill out all necessary fields.")

                else:
                    return redirect(url_for('results'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/api/result/new')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_results_new():

            try:

                if request.method == 'POST':

                    if request.is_json:
                        Content = request.get_json()

                        if all(Items in Content for Items in ["Name", "URL", "Type"]):
                            Name = Content['Name']
                            URL = Content['URL']
                            Type = Content['Type']

                            if not Validator(String_to_Check=str(Name), Safe_Characters=["-", ".", ",", ":"]):
                                return jsonify({"Error": "Bad characters identified in the name field, please remove special characters."}), 500

                            if not Type in Finding_Types:
                                Joint_Finding_Types: str = ", ".join(Finding_Types)
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

                            Iterator_List: list = list()
                            i: int = int()

                            while i < len(Hosts_List) and len(Query_List):
                                URL_Regex = Common.Regex_Handler(Hosts_List[i], Type="URL")

                                if URL_Regex:
                                    Iterator_List.append(i)
                                    i += 1

                                else:
                                    return jsonify({"Error": "Information supplied to the URL field could not be identified as a URL / URLs."}), 500

                            for Iterator in Iterator_List:
                                URL_Regex = Common.Regex_Handler(Hosts_List[Iterator], Type="URL")

                                try:
                                    Cursor.execute('INSERT INTO results (task_id, title, status, plugin, domain, link, created_at, updated_at, result_type) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)', (0, str(Query_List[Iterator]), "Open", "Manual Entry", str(URL_Regex.group(3)), str(Hosts_List[Iterator]), Common.Date(), Common.Date(), Type,))
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

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/results/delete/<resultid>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def delete_result(resultid):

            try:

                def del_result(resultid):
                    result_id = int(resultid)
                    Cursor.execute("SELECT * FROM results WHERE result_id = %s", (result_id,))
                    Result = Cursor.fetchone()   
                            
                    if Result[9] and "," in Result[9]:

                        for File in Result[9].split(", "):
                            Screenshot_File = f"{File_Path}/static/protected/screenshots/{File}"
                            
                            if os.path.exists(Screenshot_File):
                                os.remove(Screenshot_File)
                                
                    elif Result[9] and "," not in Result[9]:
                        Screenshot_File = f"{File_Path}/static/protected/screenshots/{Result[9]}"
                            
                        if os.path.exists(Screenshot_File):
                            os.remove(Screenshot_File)

                    if Result[10] and "," in Result[10]:
                    
                        for File in Result[10].split(", "):
                            Output_File = f"{File_Path}/{File}"

                            if os.path.exists(Output_File) and not any(Output_File.endswith(Ext) for Ext in [".csv", ".docx"]):
                                os.remove(Output_File)
                                
                    elif Result[10] and "," not in Result[10]:
                        Output_File = f"{File_Path}/{Result[10]}"
                        
                        if os.path.exists(Output_File) and not any(Output_File.endswith(Ext) for Ext in [".csv", ".docx"]):
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

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/api/result/delete/<resultid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_results_delete(resultid):

            try:

                if request.method == 'POST':
                    result_id = int(resultid)
                    Cursor.execute("SELECT * FROM results WHERE result_id = %s", (result_id,))
                    Result = Cursor.fetchone()

                    if not Result:
                        return jsonify({"Error": f"Unable to find result id {str(result_id)}."}), 500

                    if Result[9] and "," in Result[9]:

                        for File in Result[9].split(", "):
                            Screenshot_File = f"{File_Path}/static/protected/screenshots/{File}"
                            
                            if os.path.exists(Screenshot_File):
                                os.remove(Screenshot_File)
                                
                    elif Result[9] and "," not in Result[9]:
                        Screenshot_File = f"{File_Path}/static/protected/screenshots/{Result[9]}"
                            
                        if os.path.exists(Screenshot_File):
                            os.remove(Screenshot_File)

                    if Result[10] and "," in Result[10]:
                    
                        for File in Result[10].split(", "):
                            Output_File = f"{File_Path}/{File}"

                            if os.path.exists(Output_File) and not any(Output_File.endswith(Ext) for Ext in [".csv", ".docx"]):
                                os.remove(Output_File)
                                
                    elif Result[10] and "," not in Result[10]:
                        Output_File = f"{File_Path}/{Result[10]}"
                        
                        if os.path.exists(Output_File) and not any(Output_File.endswith(Ext) for Ext in [".csv", ".docx"]):
                            os.remove(Output_File)

                    Cursor.execute("DELETE FROM results WHERE result_id = %s;", (result_id,))
                    Connection.commit()
                    Message = f"Result ID {str(result_id)} deleted."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return jsonify({"Message": "Successfully deleted result."}), 500

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/results/changestatus/<status>/<resultid>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def change_result_status(status, resultid):

            try:

                if status in ["open", "close", "review"]:

                    def change_status_inner(resultid):

                        if status == "open":
                            Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Open", str(Common.Date()), resultid,))
                            Message = f"Result ID {str(resultid)} re-opened by {session.get('user')}."

                        elif status == "close":
                            Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Closed", str(Common.Date()), resultid,))
                            Message = f"Result ID {str(resultid)} closed by {session.get('user')}."

                        elif status == "review":
                            Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Reviewing", str(Common.Date()), resultid,))
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

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        # deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>
        @app.route('/api/result/changestatus/<status>/<resultid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_results_changestatus(status, resultid):

            try:

                if request.method == 'POST':
                    result_id = int(resultid)

                    if status == "open":
                        Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Open", str(Common.Date()), result_id,))
                        Message = f"Result ID {str(result_id)} re-opened."

                    elif status == "close":
                        Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Closed", str(Common.Date()), result_id,))
                        Message = f"Result ID {str(result_id)} closed."

                    elif status == "review":
                        Cursor.execute('UPDATE results SET status = %s, updated_at = %s WHERE result_id = %s', ("Reviewing", str(Common.Date()), result_id,))
                        Message = f"Result ID {str(result_id)} now under review."

                    Connection.commit()
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return jsonify({"Message": f"Successfully changed the status for result ID {result_id}."}), 500

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/results/details/<resultid>', methods=['GET'])
        @login_requirement
        def result_details(resultid):

            try:
                Screenshot_Request_Message = session.get("result_ss_request_message")
                session["result_ss_request_message"]: str = str()
                resultid = int(resultid)
                Cursor.execute("SELECT * FROM results WHERE result_id = %s", (resultid,))
                Result_Table_Results = Cursor.fetchone()
                Report_Files: list = list()
                Output_Files: list = list()
                Screenshot_Files: list = list()
                
                if Result_Table_Results[9] and "," in Result_Table_Results[9]:

                    for File in Result_Table_Results[9].split(", "):

                        if File.endswith(".png"):
                            Screenshot_Files.append(File)
                            
                elif Result_Table_Results[9] and "," not in Result_Table_Results[9]:
                    File = Result_Table_Results[9]
                    
                    if File.endswith(".png"):
                        Screenshot_Files.append(File)

                if Result_Table_Results[10] and "," in Result_Table_Results[10]:

                    for File in Result_Table_Results[10].split(", "):
                        Regex = Common.Regex_Handler(File, Type="File_Date")

                        if (File.endswith(".csv") or File.endswith(".docx")) and not Regex:
                            Report_Files.append(File)

                        else:
                            Output_Files.append(File)
                            
                elif Result_Table_Results[10] and "," not in Result_Table_Results[10]:
                    File = Result_Table_Results[10]
                    Regex = Common.Regex_Handler(Result_Table_Results[10], Type="File_Date")
                    
                    if (File.endswith(".csv") or File.endswith(".docx")) and not Regex:
                        Report_Files.append(File)

                    else:
                        Output_Files.append(File)

                Cursor.execute("SELECT * FROM tasks WHERE task_id = %s", (Result_Table_Results[1],))
                Task_Table_Results = Cursor.fetchone()
                return render_template('results.html', username=session.get('user'), form_step=0, details=True, is_admin=session.get('is_admin'), results=Result_Table_Results, task_results=Task_Table_Results, Report_Files=Report_Files, Output_Files=Output_Files, Screenshot_Permitted=Permit_Screenshots, Screenshot_Files=Screenshot_Files, ss_req_message=Screenshot_Request_Message)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/results/filtered', methods=['GET', 'POST'])
        @login_requirement
        def results_filtered():

            try:
                session['results_form_step']: int = int()
                SQL_Query_Start: str = "SELECT * FROM results WHERE "
                SQL_Query_End: str = " ORDER BY result_id DESC LIMIT 1000"
                SQL_Query_Args: list = list()
                Result_Filter_Values: list = list()

                for Result_Filter in Result_Filters:
                    Current_Filter_Value = str(request.args.get(Result_Filter))

                    if Current_Filter_Value and Current_Filter_Value != str():

                        if "ID" in Result_Filter:
                            Current_Filter_Value = int(Current_Filter_Value)

                        Converted_Filter = Result_Filter.lower().replace(" ", "_")
                        
                        if type(Current_Filter_Value) == int:
                            SQL_Query_Args.append(f"{Converted_Filter} = {str(Current_Filter_Value)}")

                        elif (type(Current_Filter_Value) == str and Validator(String_to_Check=str(Current_Filter_Value), Safe_Characters=Standard_Safe_Chars)):

                            if Current_Filter_Value == "*":
                                SQL_Query_Args.append(f"{Converted_Filter} != \'\'")

                            else:
                                SQL_Query_Args.append(f"{Converted_Filter} LIKE \'%{Current_Filter_Value}%\'")
                        
                        Result_Filter_Values.append(Current_Filter_Value)

                    else:
                        Result_Filter_Values.append(str())

                if len(SQL_Query_Args) > int():
                    SQL_Query_Args: str = " AND ".join(SQL_Query_Args)
                    SQL_Statement = SQL_Query_Start + SQL_Query_Args + SQL_Query_End
                    Cursor.execute(SQL_Statement)
                    return render_template('results.html', username=session.get('user'), form_step=session.get('results_form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), Finding_Types=Finding_Types, Result_Filters=Result_Filters, Result_Filter_Values=Result_Filter_Values, Result_Filter_Iterator=list(range(0, len(Result_Filters))))

                else:
                    return redirect(url_for('results'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/results', methods=['GET'])
        @login_requirement
        def results():

            try:
                session['results_form_step']: int = int()
                Cursor.execute("SELECT * FROM results ORDER BY result_id DESC LIMIT 1000")
                return render_template('results.html', username=session.get('user'), form_step=session.get('results_form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), Finding_Types=Finding_Types , Result_Filters=Result_Filters, Result_Filter_Values=list(), Result_Filter_Iterator=list(range(0, len(Result_Filters))))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('results'))

        @app.route('/api/results')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        def api_results_all():

            try:
                Auth_Token = request.headers['Authorization'].replace("Bearer ", "")
                Authentication_Verified = API_verification(Auth_Token)

                if Authentication_Verified.get("Token"):

                    if request.method == 'GET':

                        if request.is_json:
                            Content = request.get_json()
                            data: dict = dict()
                            Safe_Content: dict = dict()

                            for Item in Result_Filters:

                                if Item in Content:

                                    if not Validator(String_to_Check=str(Content[Item]), Safe_Characters=Standard_Safe_Chars):
                                        return jsonify({"Error": f"Bad characters detected in the {Item} field."}), 500

                                    if Item == "Result ID":

                                        if type(Content[Item]) != int:
                                            return jsonify({"Error": f"The ID provided is not an integer."}), 500

                                        Safe_Content["result_id"] = Content[Item]

                                    elif Item == "Task ID":
                                        Safe_Content["task_id"] = Content[Item]

                                    elif " " in Item:
                                        Safe_Content[Item.lower().replace(" ", "_")] = Content[Item]

                                    else:
                                        Safe_Content[Item.lower()] = Content[Item]

                            if len(Safe_Content) > 1:
                                Select_Query: str = "SELECT * FROM results WHERE "

                                for Item_Key, Item_Value in sorted(Safe_Content.items()):
                                    Select_Query += f"{Item_Key} = '{Item_Value}'"

                                    if Item_Key != sorted(Safe_Content.keys())[-1]:
                                        Select_Query += " AND "

                                    else:
                                        Select_Query += ";"

                                Cursor.execute(Select_Query)

                            elif len(Safe_Content) == 1:
                                Key = list(Safe_Content.keys())[0]
                                Val = list(Safe_Content.values())[0]
                                Select_Query: str = "SELECT * FROM results WHERE "
                                Select_Query += f"{Key} = '{Val}'"
                                Cursor.execute(Select_Query)

                            else:
                                return jsonify({"Error": "No valid fields found in request."}), 500

                            for Result in Cursor.fetchall():
                                data[Result[0]] = {"Associated Task ID": Result[1], "Title": Result[2], "Plugin": Result[3], "Status": Result[4], "Domain": Result[5], "Link": Result[6], "Created Timestamp": Result[7], "Last Updated Timestamp": Result[8], "Screenshot Location": Result[9], "Output File Location": Result[10], "Result Type": Result[11], "Screenshot Requested": Result[12]}

                            return jsonify(data), 200

                        else:
                            data: dict = dict()
                            Cursor.execute('SELECT * FROM results ORDER BY result_id DESC LIMIT 1000')

                            for Result in Cursor.fetchall():
                                data[Result[0]] = {"Associated Task ID": Result[1], "Title": Result[2], "Plugin": Result[3], "Status": Result[4], "Domain": Result[5], "Link": Result[6], "Created Timestamp": Result[7], "Last Updated Timestamp": Result[8], "Screenshot Location": Result[9], "Output File Location": Result[10], "Result Type": Result[11], "Screenshot Requested": Result[12]}

                            return jsonify(data), 200

                    else:
                        return jsonify({"Error": "Method not allowed."}), 500

            except:
                return jsonify({"Error": "Unknown error."}), 500

        def check_security_requirements(Password):

            try:

                if len(Password) < 8:
                    return False

                else:
                    Lower = any(Letter.islower() for Letter in Password)
                    Upper = any(Letter.isupper() for Letter in Password)
                    Digit = any(Letter.isdigit() for Letter in Password)

                    if not Upper or not Lower or not Digit:
                        return False

                    else:
                        Special_Character_Regex = Common.Regex_Handler(Password, Type="Password_Special_Characters")

                        if not Special_Character_Regex:
                            return False

                        else:
                            return True

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('dashboard'))
# deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>

        @app.route('/api/account/new')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_accounts_new():

            try:

                if request.method == 'POST':

                    if request.is_json:
                        Content = request.get_json()

                        if all(Items in Content for Items in ["Username", "Password", "Password Retype", "Administrator"]):

                            if not Content['Username']:
                                return jsonify({"Error": "Please provide a valid username."}), 500

                            if not Content['Username'].isalnum():
                                return jsonify({"Error": "One or more bad character detected in username. Please ensure the provided username only contains letters and numbers."}), 500

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

                                    if Content["Administrator"]:
                                        Cursor.execute('INSERT INTO users (username, password, blocked, is_admin) VALUES (%s,%s,%s,%s)',(Content['Username'], Password, "False", "True",))
                                        Message = f"New administrative user {Content['Username']} created."

                                    else:
                                        Cursor.execute('INSERT INTO users (username, password, blocked, is_admin) VALUES (%s,%s,%s,%s)',(Content['Username'], Password, "False", "False",))
                                        Message = f"New low-privileged user {Content['Username']} created."

                                    Connection.commit()
                                    Create_Event(Message)
                                    return jsonify({"Message": f"Successfully created user {Content['Username']}."}), 200

                        else:
                            return jsonify({"Error": "One or more fields has not been provided."}), 500

                    else:
                        return jsonify({"Error": "Request is not in JSON format."}), 500

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/settings/account/new', methods=['POST', 'GET'])
        @login_requirement
        @admin_requirement
        def new_account():

            try:

                if session.get('settings_form_step') == 0 or request.method == "GET":
                    session['settings_form_step'] = 1
                    session['settings_form_type']: str = "CreateUser"
                    return render_template('settings.html', username=session.get('user'),
                                           form_type=session.get('settings_form_type'), form_step=session.get('settings_form_step'),
                                           is_admin=session.get('is_admin'), api_key=session.get('api_key'),
                                           current_user_id=session.get('user_id'))

                elif session.get('settings_form_step') == 1:
                    time.sleep(1)

                    if not request.form['Username']:
                        return render_template('settings.html', username=session.get('user'),
                                               form_type=session.get('settings_form_type'), form_step=session.get('settings_form_step'),
                                               is_admin=session.get('is_admin'), results=Cursor.fetchall(),
                                               error="Please provide a valid username.", api_key=session.get('api_key'),
                                               current_user_id=session.get('user_id'))

                    if not request.form['Username'].isalnum():
                        return render_template('settings.html', username=session.get('user'),
                                                   form_type=session.get('settings_form_type'),
                                                   form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'),
                                                   results=Cursor.fetchall(),
                                                   error="One or more bad character detected in username. Please ensure the provided username only contains letters and numbers.",
                                                   api_key=session.get('api_key'),
                                                   current_user_id=session.get('user_id'))

                    Cursor.execute('SELECT * FROM users WHERE username = %s', (request.form.get('Username'),))
                    User = Cursor.fetchone()

                    if User:
                        Cursor.execute('SELECT * FROM users')
                        return render_template('settings.html', username=session.get('user'),
                                               form_type=session.get('settings_form_type'), form_step=session.get('settings_form_step'),
                                               is_admin=session.get('is_admin'), results=Cursor.fetchall(),
                                               error="Username already exists.", api_key=session.get('api_key'),
                                               current_user_id=session.get('user_id'))

                    Cursor.execute('SELECT * FROM users')

                    if request.form['New_Password'] != request.form['New_Password_Retype']:
                        return render_template('settings.html', username=session.get('user'),
                                               form_type=session.get('settings_form_type'), form_step=session.get('settings_form_step'),
                                               is_admin=session.get('is_admin'), results=Cursor.fetchall(),
                                               error="Please make sure the \"New Password\" and \"Retype Password\" fields match.",
                                               api_key=session.get('api_key'), current_user_id=session.get('user_id'))

                    else:

                        if not check_security_requirements(request.form['New_Password']):
                            return render_template('settings.html', username=session.get('user'),
                                                   form_type=session.get('settings_form_type'),
                                                   form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'),
                                                   results=Cursor.fetchall(), requirement_error=[
                                    "The supplied password does not meet security requirements. Please make sure the following is met:",
                                    "- The password is longer than 8 characters.",
                                    "- The password contains 1 or more UPPERCASE and 1 or more lowercase characters.",
                                    "- The password contains 1 or more numbers.",
                                    "- The password contains one or more special characters. Ex. @."],
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
                            app.logger.warning(Message)
                            Create_Event(Message)
                            return render_template('settings.html', username=session.get('user'),
                                                   form_type=session.get('settings_form_type'),
                                                   form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'),
                                                   results=Cursor.fetchall(), message=Message,
                                                   api_key=session.get('api_key'),
                                                   current_user_id=session.get('user_id'))

                else:
                    return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/account/password/change/<accountid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_accounts_password_change(accountid):

            try:

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

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/settings/account/password/change/<account>', methods=['POST', 'GET'])
        @login_requirement
        def change_account_password(account):

            try:

                if str(account) == "mine" and 'Current_Password' in request.form and 'New_Password' in request.form and 'New_Password_Retype' in request.form and request.method == "POST":
                    time.sleep(1)
                    Current_Password = request.form['Current_Password']
                    Cursor.execute('SELECT * FROM users WHERE username = %s', (session.get('user'),))
                    User = Cursor.fetchone()

                    if not check_password_hash(User[2], Current_Password):
                        session["na_settings_error"]: str = "Current Password is incorrect."
                        return redirect(url_for('account'))

                    else:

                        if request.form['New_Password'] != request.form['New_Password_Retype']:
                            session["na_settings_error"]: str = "Please make sure the \"New Password\" and \"Retype Password\" fields match."
                            return redirect(url_for('account'))

                        else:

                            if not check_password_hash(User[2], request.form['New_Password']):

                                if not check_security_requirements(request.form['New_Password']):
                                    session["na_req_settings_error"] = [
                                            "The supplied password does not meet security requirements. Please make sure the following is met:",
                                            "- The password is longer than 8 characters.",
                                            "- The password contains 1 or more UPPERCASE and 1 or more lowercase characters.",
                                            "- The password contains 1 or more numbers.",
                                            "- The password contains one or more special characters. Ex. @."]
                                    return redirect(url_for('account'))

                                else:
                                    password = generate_password_hash(request.form['New_Password'])
                                    Cursor.execute('UPDATE users SET password = %s WHERE user_id = %s', (password, User[0],))
                                    Connection.commit()
                                    session["na_settings_message"]: str = "Password successfully changed."
                                    return redirect(url_for('account'))

                            else:
                                session["na_settings_error"]: str = "Your current password and new password cannot be identical."
                                return redirect(url_for('account'))

                else:

                    if session.get('is_admin'):

                        if session.get('settings_form_step') == 0 or request.method == "GET":
                            session['other_user_id'] = int(account)
                            session['settings_form_step'] = 1
                            session['settings_form_type']: str = "ChangePassword"
                            return render_template('settings.html', username=session.get('user'),
                                                   form_type=session.get('settings_form_type'),
                                                   form_step=session.get('settings_form_step'),
                                                   is_admin=session.get('is_admin'), api_key=session.get('api_key'),
                                                   current_user_id=session.get('other_user_id'))

                        elif session.get('settings_form_step') == 1:
                            time.sleep(1)
                            Cursor.execute('SELECT * FROM users WHERE user_id = %s', (session.get('other_user_id'),))
                            User = Cursor.fetchone()

                            if request.form['New_Password'] != request.form['New_Password_Retype']:
                                return render_template('settings.html', username=session.get('user'),
                                                       form_type=session.get('settings_form_type'),
                                                       form_step=session.get('settings_form_step'),
                                                       is_admin=session.get('is_admin'),
                                                       error="Please make sure the \"New Password\" and \"Retype Password\" fields match.",
                                                       api_key=session.get('api_key'),
                                                       current_user_id=session.get('other_user_id'))

                            else:
                                Password_Security_Requirements_Check = check_security_requirements(request.form['New_Password'])

                                if not Password_Security_Requirements_Check:
                                    return render_template('settings.html', username=session.get('user'),
                                                           form_type=session.get('settings_form_type'),
                                                           form_step=session.get('settings_form_step'),
                                                           is_admin=session.get('is_admin'), requirement_error=[
                                            "The supplied password does not meet security requirements. Please make sure the following is met:",
                                            "- The password is longer than 8 characters.",
                                            "- The password contains 1 or more UPPERCASE and 1 or more lowercase characters.",
                                            "- The password contains 1 or more numbers.",
                                            "- The password contains one or more special characters. Ex. @."],
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

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/settings/account/api/token/get', methods=['POST', 'GET'])
        @login_requirement
        def get_account_apikey():

            try:

                def Create_Session_Based_JWT(ID, Username):
                    Expiry_Hours = API_Validity_Limit / 60
                    Expiry = datetime.utcnow() + timedelta(hours=Expiry_Hours)
                    payload = {"id": ID, "name": Username, "iat": datetime.utcnow(), "exp": Expiry, "nonce": secrets.token_hex(32)}
                    JWT = jwt.encode(payload, API_Secret, algorithm='HS256')
                    return JWT.decode('utf-8')

                user_id = int(session.get('user_id'))
                Cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
                User_Info = Cursor.fetchone()

                if User_Info[5] and User_Info[6]:

                    try:
                        jwt.decode(User_Info[5], API_Secret, algorithm='HS256')
                        session['apigen_settings_message']: str = "Current token is still valid."
                        return redirect(url_for('account'))

                    except:
                        API_Key = Create_Session_Based_JWT(User_Info[0], User_Info[1])
                        Cursor.execute('UPDATE users SET api_key = %s, api_generated_time = %s WHERE user_id = %s', (API_Key, Common.Date(), User_Info[0],))
                        Connection.commit()
                        Message = f"New API token generated for user ID {str(user_id)} by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)
                        session['api_key'] = API_Key
                        session['apigen_settings_message']: str = "New API token generated successfully."
                        return redirect(url_for('account'))

                else:
                    API_Key = Create_Session_Based_JWT(User_Info[0], User_Info[1])
                    Cursor.execute('UPDATE users SET api_key = %s, api_generated_time = %s WHERE user_id = %s', (API_Key, Common.Date(), User_Info[0],))
                    Connection.commit()
                    Message = f"New API Key generated for user ID {str(user_id)} by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    session['api_key'] = API_Key
                    session['apigen_settings_message']: str = "New API token generated successfully."
                    return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/settings/account/mfa/token', methods=['POST', 'GET'])
        @login_requirement
        def get_account_mfa_token():

            try:

                if request.method == "GET":
                    user_id = int(session.get('user_id'))
                    Cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
                    User_Info = Cursor.fetchone()
                    Base32_Secret = pyotp.random_base32()
                    TOTP = pyotp.totp.TOTP(Base32_Secret).provisioning_uri(name=User_Info[1], issuer_name='Scrummage')
                    Cursor.execute('UPDATE users SET mfa_token = %s, mfa_confirmed = %s WHERE user_id = %s', (Base32_Secret, False, User_Info[0],))
                    Connection.commit()
                    Cursor.execute('SELECT * FROM users ORDER BY user_id')
                    return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), api_key=session.get('api_key'), current_user_id=session.get('user_id'), mfa_form=True, MFA_URL=TOTP)

                elif request.method == "POST":
                    user_id = int(session.get('user_id'))
                    Cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
                    User_Info = Cursor.fetchone()
                    TOTP = pyotp.TOTP(User_Info[7])

                    if request.form.get("mfa_token") and (request.form["mfa_token"] == TOTP.now()):
                        Cursor.execute('UPDATE users SET mfa_confirmed = %s WHERE user_id = %s', (True, User_Info[0],))
                        Connection.commit()
                        session['apigen_settings_message']: str = "MFA successfully set up."
                        return redirect(url_for('account'))

                    else:
                        return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), api_key=session.get('api_key'), current_user_id=session.get('user_id'), mfa_form=True, MFA_URL=TOTP, verification_error="Failed to verify supplied token.")

                else:
                    return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        # deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>, deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>, deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>
        @app.route('/api/account/delete/<accountid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_accounts_delete(accountid):

            try:

                if request.method == 'POST':
                    user_id = int(accountid)
                    Cursor.execute("DELETE FROM users WHERE user_id = %s;", (user_id,))
                    Connection.commit()
                    Message = f"User ID {str(user_id)} deleted."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return jsonify({"Message": f"Successfully deleted user {str(user_id)}."}), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/settings/account/delete/<accountid>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def delete_account(accountid):

            try:

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

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        # deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>, deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>, deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>, deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>
        # deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>
        @app.route('/api/account/disable/<accountid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_accounts_disable(accountid):

            try:

                if request.method == 'POST':
                    user_id = int(accountid)
                    Cursor.execute('UPDATE users SET blocked = %s WHERE user_id = %s', ("True", user_id,))
                    Connection.commit()
                    Message = f"User ID {str(user_id)} blocked."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return jsonify({"Message": f"Successfully blocked user {str(user_id)}."}), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/settings/account/disable/<accountid>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def disable_account(accountid):

            try:

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

            except Exception as e:
                app.logger.error(e)
                # deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>, deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>
                return redirect(url_for('account'))

        @app.route('/api/account/enable/<accountid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_accounts_enable(accountid):

            try:

                if request.method == 'POST':
                    user_id = int(accountid)
                    Cursor.execute('UPDATE users SET blocked = %s WHERE user_id = %s', ("False", user_id,))
                    Connection.commit()
                    Message = f"User ID {str(user_id)} unblocked."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return jsonify({"Message": f"Successfully unblocked user {str(user_id)}."}), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/settings/account/enable/<accountid>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def enable_account(accountid):

            try:

                def enable_account_inner(accountid):
                    user_id = int(accountid)
                    Cursor.execute('UPDATE users SET blocked = %s WHERE user_id = %s', ("False", user_id,))
                    Connection.commit()
                    Message = f"User ID {str(user_id)} unblocked by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)

                if "," in accountid:

                    for userid in accountid.split(","):
                        enable_account_inner(userid)

                else:
                    enable_account_inner(accountid)

                return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        # deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>, deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>, deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>, deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>, deepcode ignore DisablesCSRFProtection: <please specify a reason of ignoring this>
        @app.route('/api/account/demote/<accountid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_accounts_demote(accountid):

            try:

                if request.method == 'POST':
                    user_id = int(accountid)
                    Cursor.execute('UPDATE users SET is_admin = %s WHERE user_id = %s', ("False", user_id,))
                    Connection.commit()
                    Message = f"Privileges for user ID {str(user_id)} demoted."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return jsonify({"Message": f"Successfully demoted user {str(user_id)}."}), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/settings/account/demote/<accountid>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def demote_account(accountid):

            try:

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

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/account/promote/<accountid>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_accounts_promote(accountid):

            try:

                if request.method == 'POST':
                    user_id = int(accountid)
                    Cursor.execute('UPDATE users SET is_admin = %s WHERE user_id = %s', ("True", user_id,))
                    Connection.commit()
                    Message = f"Privileges for user ID {str(user_id)} promoted."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return jsonify({"Message": f"Successfully promoted user {str(user_id)}."}), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/settings/account/promote/<accountid>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def promote_account(accountid):

            try:

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

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/settings/account', methods=['GET'])
        @login_requirement
        def account():

            try:

                if session.get('is_admin'):
                    Cursor.execute('SELECT * FROM users ORDER BY user_id')
                    Admin_Results = Cursor.fetchall()

                else:
                    Admin_Results = ()

                Cursor.execute('SELECT * FROM users WHERE user_id = %s', (session.get("user_id"),))
                User_Details = Cursor.fetchone()
            
                if session.get('apigen_settings_message'):
                    Settings_Message = session.get('apigen_settings_message')
                    session['apigen_settings_message']: str = str()
                    return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), mfainuse=(User_Details[8] == "true"), results=Admin_Results, api_key=session.get('api_key'), current_user_id=session.get('user_id'), message=Settings_Message)

                elif session.get('mfa_error') and session.get('is_admin'):
                    MFA_Error = session.get('mfa_error')
                    session['mfa_error']: str = str()
                    return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), mfainuse=(User_Details[8] == "true"), results=Admin_Results, api_key=session.get('api_key'), current_user_id=session.get('user_id'), error=MFA_Error)

                else:
                    Settings_Message: str = str()

                    if session.get('is_admin'):
                    
                        if not session.get('apigen_settings_message'):
                            Settings_Message = session.get('settings_message')

                        session['settings_message']: str = str()
                        session['mfa_error']: str = str()
                        session['settings_form_step']: int = int()
                        session['settings_form_type']: str = str()
                        session['other_user_id']: int = int()
                        return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), mfainuse=(User_Details[8] == "true"), results=Admin_Results, api_key=session.get('api_key'), current_user_id=session.get('user_id'), Account_Filters=Account_Filters, Account_Filter_Values=list(), Account_Filter_Iterator=list(range(0, len(Account_Filters))), message=Settings_Message)

                    else:
                        Form_Settings_Message = session.get('na_settings_message')
                        Form_Settings_Error = session.get('na_settings_error')
                        Req_Error = session.get('na_req_settings_error')
                        MFA_Error = session.get('mfa_error')
                        session['na_settings_error']: str = str()
                        session['na_req_settings_error']: list = list()
                        session['na_settings_message']: str = str()
                        session['mfa_error']: str = str()
                        return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), mfainuse=(User_Details[8] == "true"), api_key=session.get('api_key'), current_user_id=session.get('user_id'), form_error=Form_Settings_Error, form_message=Form_Settings_Message, requirement_error=Req_Error, message=Settings_Message, MFA_Error=MFA_Error)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/settings/configurations/<configtype>')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_settings_get_configuration(configtype):

            try:

                if request.method == 'GET':

                    if configtype == "inputs":
                        Object = Common.Configuration(Input=True)

                    elif configtype == "outputs":
                        Object = Common.Configuration(Output=True)

                    elif configtype == "core":
                        Object = Common.Configuration(Core=True)

                    else:
                        return jsonify({"Error": "Invalid configuration type, please select from inputs, outputs, or core."}), 500

                    List_of_Inputs = Object.Load_Keys()
                    Final_List: list = list()

                    if "web_app" in List_of_Inputs:
                        List_of_Inputs.remove("web_app")

                    for Obj in List_of_Inputs:
                        Data = Object.Load_Values(Object=Obj)
                        Final_List.append({Obj: Data})

                    return jsonify({configtype: Final_List}), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/api/settings/configure/<configtype>')
        @csrf.exempt
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_settings_set_configuration(configtype):

            try:

                if request.method == 'POST':
                    Content = request.get_json()

                    if all(Content_Item in Content for Content_Item in ["object", "data"]):

                        if configtype == "inputs":
                            Object = Common.Configuration(Input=True)

                        elif configtype == "outputs":
                            Object = Common.Configuration(Output=True)

                        elif configtype == "core":
                            Object = Common.Configuration(Core=True)

                        else:
                            return jsonify({"Error": "Invalid configuration type, please select from inputs, outputs, or core."}), 500

                        Data_Items = Object.Load_Values(Object=Content["object"])

                        if all(Item in Content["data"] for Item in Data_Items.keys()):
                            New_Config: dict = dict()

                            for Item_Key, Item_Value in Content["data"].items():

                                if Item_Key in Data_Items:

                                    if type(Data_Items[Item_Key]) == int:
                                        Item_Value = int(Item_Value)
                                        New_Config[Item_Key] = Item_Value

                                    elif type(Data_Items[Item_Key]) == bool:
                                        New_Config[Item_Key] = Item_Value

                                    else:
                                        Item_Value = str(Item_Value)
                                        New_Config[Item_Key] = Item_Value

                            Result = Object.Set_Field(Object=Content["object"], Config=New_Config)

                            if Result:
                                return jsonify({"Message": "Successfully updated " + configtype + " > " + Content["object"] + "."}), 200

                            else:
                                return jsonify({"Error": "Failed to update " + configtype + " > " + Content["object"] + "."}), 500

                        else:
                            return jsonify({"Error": "Invalid fields provided."}), 500

                    else:
                        return jsonify({"Error": "Invalid fields provided."}), 500

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/settings/configure/<configtype>', methods=['GET'])
        @login_requirement
        @admin_requirement
        def configure(configtype):

            try:
                session['settings_form_step']: int = int()
                session['settings_form_type']: str = str()
                session['item']: str = str()
                session['item_list']: list = list()
                session['config_list']: list = list()

                if configtype == "inputs":
                    Object = Common.Configuration(Input=True)

                elif configtype == "outputs":
                    Object = Common.Configuration(Output=True)

                elif configtype == "core":
                    Object = Common.Configuration(Core=True)

                else:
                    Cursor.execute('SELECT * FROM users ORDER BY user_id')
                    return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), error="Invalid input type provided.")

                session['settings_form_type'] = configtype
                List_of_Inputs = Object.Load_Keys()

                if "web_app" in List_of_Inputs:
                    List_of_Inputs.remove("web_app")

                session['config_list'] = List_of_Inputs
                return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), List_of_Inputs=List_of_Inputs, Configure=True)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/settings/configure/object', methods=['POST'])
        @login_requirement
        @admin_requirement
        def configure_item():

            try:

                if session.get('settings_form_step') == 0 and session.get('settings_form_type') != str() and "item" in request.form and request.form['item'] in session.get('config_list'):
                    time.sleep(1)
                    item = request.form['item']
                    configtype = session.get('settings_form_type')
                    session['settings_form_step'] = 1

                    if configtype == "inputs":
                        Object = Common.Configuration(Input=True)

                    elif configtype == "outputs":
                        Object = Common.Configuration(Output=True)

                    elif configtype == "core":
                        Object = Common.Configuration(Core=True)

                    else:
                        List_of_Inputs = session['config_list']
                        return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), List_of_Inputs=List_of_Inputs, Configure=True, error="Invalid configuration type provided.")

                    List_of_Item_Values = Object.Load_Values(Object=item)
                    session['item_list'] = List_of_Item_Values
                    session['item'] = item
                    return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), List_of_Item_Values=List_of_Item_Values.items(), Configure=True, Config_Type_Upper=session['settings_form_type'].capitalize(), Config_Type=session['settings_form_type'])

                elif session.get('settings_form_step') == 1 and session.get('settings_form_type') != str():
                    time.sleep(1)

                    if all(Item in request.form for Item, Val in session['item_list'].items()):
                        item = session.get('item')
                        New_Config: dict = dict()

                        for Item_Key, Item_Value in request.form.items():

                            if Item_Key in session['item_list']:

                                if type(session['item_list'][Item_Key]) == int:
                                    Item_Value = int(Item_Value)
                                    New_Config[Item_Key] = Item_Value

                                elif type(session['item_list'][Item_Key]) == bool:
                                    import distutils.util
                                    Item_Value = bool(distutils.util.strtobool(Item_Value))
                                    New_Config[Item_Key] = Item_Value

                                elif session.get('item') == "organisation" and Item_Key == "subdomains":
                                    Item_Value = Item_Value.replace("\'", "\"")
                                    Item_Value = Common.JSON_Handler(Item_Value).To_JSON_Loads()
                                    New_Config[Item_Key] = Item_Value

                                else:
                                    Item_Value = str(Item_Value)
                                    New_Config[Item_Key] = Item_Value

                        configtype = session.get('settings_form_type')
                        session['settings_form_step'] = 1

                        if configtype == "inputs":
                            Object = Common.Configuration(Input=True)

                        elif configtype == "outputs":
                            Object = Common.Configuration(Output=True)

                        elif configtype == "core":
                            Object = Common.Configuration(Core=True)

                        else:
                            List_of_Item_Values = session['item_list']
                            return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), List_of_Item_Values=List_of_Item_Values.items(), Configure=True, error="Invalid configuration type provided.")

                        Message_Configtype = configtype.replace("s", "")
                        Result = Object.Set_Field(Object=item, Config=New_Config)

                        if Result:
                            session['settings_message'] = f"Successfully updated configuration for {Message_Configtype} > {str(item)}"
                            return redirect(url_for('account'))

                        else:
                            return redirect(url_for('account'))

                    else:
                        List_of_Item_Values = session['item_list']
                        return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), List_of_Item_Values=List_of_Item_Values.items(), Configure=True, error="One or more required fields were missing from the request.")

                else:
                    return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))        

        @app.route('/settings/account/filtered', methods=['GET', 'POST'])
        @login_requirement
        @admin_requirement
        def account_filtered():

            try:
                session['settings_form_step']: int = int()
                session['settings_form_type']: str = str()
                session['other_user_id']: int = int()
                SQL_Query_Start: str = "SELECT * FROM users WHERE "
                SQL_Query_End: str = " ORDER BY user_id DESC LIMIT 1000"
                SQL_Query_Args: list = list()
                Account_Filter_Values: list = list()
        
                for Account_Filter in Account_Filters:
                    Current_Filter_Value = str(request.args.get(Account_Filter))

                    if Current_Filter_Value and Current_Filter_Value != str():

                        if "ID" in Account_Filter:
                            Current_Filter_Value = int(Current_Filter_Value)

                        Converted_Filter = Account_Filter.lower().replace(" ", "_")
                    
                        if type(Current_Filter_Value) == int:
                            SQL_Query_Args.append(f"{Converted_Filter} = {str(Current_Filter_Value)}")

                        elif type(Current_Filter_Value) == str and Converted_Filter in ("blocked", "is_admin"):
                            SQL_Query_Args.append(f"{Converted_Filter} = {str(Current_Filter_Value)}")

                        elif Current_Filter_Value == "*":
                            SQL_Query_Args.append(f"{Converted_Filter} != \'\'")
                        
                        elif (type(Current_Filter_Value) == str and Validator(String_to_Check=str(Current_Filter_Value), Safe_Characters=Standard_Safe_Chars)):
                            SQL_Query_Args.append(f"{Converted_Filter} LIKE \'%{Current_Filter_Value}%\'")
                        
                        Account_Filter_Values.append(Current_Filter_Value)

                    else:
                        Account_Filter_Values.append(str())

                if len(SQL_Query_Args) > int():
                    SQL_Query_Args: str = " AND ".join(SQL_Query_Args)
                    SQL_Statement = SQL_Query_Start + SQL_Query_Args + SQL_Query_End
                    Cursor.execute(SQL_Statement)
                    return render_template('settings.html', username=session.get('user'), form_step=session.get('settings_form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), api_key=session.get('api_key'), current_user_id=session.get('user_id'), Account_Filters=Account_Filters, Account_Filter_Values=Account_Filter_Values, Account_Filter_Iterator=list(range(0, len(Account_Filters))))

                else:
                    return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/accounts')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_account_details():

            try:

                if request.method == 'GET':

                    if request.is_json:
                        Content = request.get_json()
                        data: dict = dict()
                        Safe_Content: dict = dict()

                        for Item in Account_Filters:

                            if Item in Content:

                                if not Validator(String_to_Check=str(Content[Item]), Safe_Characters=Restricted_Safe_Chars):
                                    return jsonify({"Error": f"Bad characters detected in the {Item} field."}), 500

                                if Item == "User ID":

                                    if type(Content[Item]) != int:
                                        return jsonify({"Error": f"The ID provided is not an integer."}), 500

                                    else:
                                        Safe_Content["user_id"] = Content[Item]

                                elif Item == "Is Admin":
                                    Safe_Content["is_admin"] = Content[Item]

                                else:
                                    Safe_Content[Item.lower()] = Content[Item]

                        if len(Safe_Content) > 1:
                            Select_Query: str = "SELECT * FROM users WHERE "

                            for Item_Key, Item_Value in sorted(Safe_Content.items()):
                                Select_Query += f"{Item_Key} = '{Item_Value}'"

                                if Item_Key != sorted(Safe_Content.keys())[-1]:
                                    Select_Query += " AND "

                                else:
                                    Select_Query += ";"

                            Cursor.execute(Select_Query)

                        elif len(Safe_Content) == 1:
                            Key = list(Safe_Content.keys())[0]
                            Val = list(Safe_Content.values())[0]
                            Select_Query: str = "SELECT * FROM users WHERE "
                            Select_Query += f"{Key} = '{Val}'"
                            Cursor.execute(Select_Query)

                        else:
                            return jsonify({"Error": "No valid fields found in request."}), 500

                        for User in Cursor.fetchall():
                            data[User[0]] = [{"Username": User[1], "Blocked": User[3], "Administrative Rights": User[4]}]

                        return jsonify(data), 200

                    else:
                        data: dict = dict()
                        Cursor.execute('SELECT * FROM users ORDER BY user_id DESC LIMIT 1000')

                        for User in Cursor.fetchall():
                            data[User[0]] = [{"Username": User[1], "Blocked": User[3], "Administrative Rights": User[4]}]

                        return jsonify(data), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/identities', methods=['GET'])
        @login_requirement
        @admin_requirement
        def identities():

            try:
                Identity_Message = session.get('identities_message')
                Identity_Error = session.get('identities_error')
                session['identities_message']: str = str()
                session['identities_error']: str = str()
                session['identities_form_step']: int = int()
                session['identities_form_type']: str = str()
                Cursor.execute("SELECT * FROM org_identities ORDER BY identity_id DESC LIMIT 1000")
                return render_template('identities.html', username=session.get('user'), form_step=session.get('identities_form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), Identity_Filters=Identity_Filters, Identity_Filter_Values=list(), Identity_Filter_Iterator=list(range(0, len(Identity_Filters))), message=Identity_Message, error=Identity_Error)

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('identities'))

        @app.route('/api/identities')
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        @api_auth_requirement
        @api_admin_requirement
        def api_identity_details():

            try:

                if request.method == 'GET':

                    if request.is_json:
                        Content = request.get_json()
                        data: dict = dict()
                        Safe_Content: dict = dict()

                        for Item in Identity_Filters:

                            if Item in Content:

                                if not Validator(String_to_Check=str(Content[Item]), Safe_Characters=Standard_Safe_Chars):
                                    return jsonify({"Error": f"Bad characters detected in the {Item} field."}), 500

                                if Item == "Identity ID":

                                    if type(Content[Item]) != int:
                                        return jsonify({"Error": "The ID provided is not an integer."}), 500

                                    else:
                                        Safe_Content["identity_id"] = Content[Item]

                                else:
                                    Safe_Content[Item.lower()] = Content[Item]

                        if len(Safe_Content) > 1:
                            Select_Query: str = "SELECT * FROM org_identities WHERE "

                            for Item_Key, Item_Value in sorted(Safe_Content.items()):
                                Select_Query += f"{Item_Key} = '{Item_Value}'"

                                if Item_Key != sorted(Safe_Content.keys())[-1]:
                                    Select_Query += " AND "

                                else:
                                    Select_Query += ";"

                            Cursor.execute(Select_Query)

                        elif len(Safe_Content) == 1:
                            Key = list(Safe_Content.keys())[0]
                            Val = list(Safe_Content.values())[0]
                            Select_Query: str = "SELECT * FROM org_identities WHERE "
                            Select_Query += f"{Key} = '{Val}'"
                            Cursor.execute(Select_Query)

                        else:
                            return jsonify({"Error": "No valid fields found in request."}), 500

                        for Identity in Cursor.fetchall():
                            data[Identity[0]] = {"Fullname": Identity[4], "Username": Identity[5], "Email": Identity[6], "Phone": Identity[7]}

                        return jsonify(data), 200

                    else:
                        data: dict = dict()
                        Cursor.execute('SELECT * FROM org_identities ORDER BY identity_id DESC LIMIT 1000')

                        for Identity in Cursor.fetchall():
                            data[Identity[0]] = {"Fullname": Identity[4], "Username": Identity[5], "Email": Identity[6], "Phone": Identity[7]}

                        return jsonify(data), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/identities/filtered', methods=['GET', 'POST'])
        @login_requirement
        @admin_requirement
        def identities_filtered():

            try:
                session['identities_form_step']: int = int()
                session['identities_form_type']: str = str()
                SQL_Query_Start: str = "SELECT * FROM org_identities WHERE "
                SQL_Query_End: str = " ORDER BY identity_id DESC LIMIT 1000"
                SQL_Query_Args: list = list()
                Identity_Filter_Values: list = list()
        
                for Identity_Filter in Identity_Filters:
                    Current_Filter_Value = str(request.args.get(Identity_Filter))

                    if Current_Filter_Value and Current_Filter_Value != str():

                        if "ID" in Identity_Filter:
                            Current_Filter_Value = int(Current_Filter_Value)

                        Converted_Filter = Identity_Filter.lower().replace(" ", "_")
                    
                        if type(Current_Filter_Value) == int:
                            SQL_Query_Args.append(f"{Converted_Filter} = {str(Current_Filter_Value)}")

                        elif Current_Filter_Value == "*":
                            SQL_Query_Args.append(f"{Converted_Filter} != \'\'")
                        
                        elif (type(Current_Filter_Value) == str and Validator(String_to_Check=str(Current_Filter_Value), Safe_Characters=Standard_Safe_Chars)):
                            SQL_Query_Args.append(f"{Converted_Filter} LIKE \'%{Current_Filter_Value}%\'")
                        
                        Identity_Filter_Values.append(Current_Filter_Value)

                    else:
                        Identity_Filter_Values.append(str())

                if len(SQL_Query_Args) > int():
                    SQL_Query_Args: str = " AND ".join(SQL_Query_Args)
                    SQL_Statement = SQL_Query_Start + SQL_Query_Args + SQL_Query_End
                    Cursor.execute(SQL_Statement)
                    return render_template('identities.html', username=session.get('user'), form_step=session.get('identities_form_step'), is_admin=session.get('is_admin'), results=Cursor.fetchall(), Identity_Filters=Identity_Filters, Identity_Filter_Values=Identity_Filter_Values, Identity_Filter_Iterator=list(range(0, len(Identity_Filters))))

                else:
                    return redirect(url_for('identities'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('identities'))

        @app.route('/identities/delete/<identity_id>', methods=['POST'])
        @login_requirement
        @admin_requirement
        def delete_identity(identity_id):

            try:

                def del_account(identity_id):
                    user_id = int(identity_id)
                    Cursor.execute("DELETE FROM org_identities WHERE identity_id = %s;", (identity_id,))
                    Connection.commit()
                    Message = f"Identity ID {str(user_id)} deleted by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)

                if "," in identity_id:

                    for userid in identity_id.split(","):
                        del_account(userid)

                else:
                    del_account(identity_id)

                return redirect(url_for('account'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('account'))

        @app.route('/api/identity/delete/<identity_id>')
        @csrf.exempt
        @api_auth_requirement
        @api_admin_requirement
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_identities_delete(identity_id):

            try:

                if request.method == 'POST':
                    identity_id = int(identity_id)
                    Cursor.execute("DELETE FROM org_identities WHERE user_id = %s;", (identity_id,))
                    Connection.commit()
                    Message = f"User ID {str(identity_id)} deleted."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    return jsonify({"Message": f"Successfully deleted identity {str(identity_id)}."}), 200

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/identities/new', methods=['POST', 'GET'])
        @login_requirement
        @admin_requirement
        def new_identity():

            try:

                if session.get('identities_form_step') == 0 or request.method == "GET":
                    session['identities_form_step'] = 1
                    session['identities_form_type']: str = "new"
                    return render_template('identities.html', username=session.get('user'),
                                            form_type=session.get('identities_form_type'),
                                            is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'))

                elif session.get('identities_form_step') == 1:
                    time.sleep(1)
                    Full_Fields = ["First", "Middle", "Surname", "Fullname", "Username", "Email", "Phone"]
                    Required_Fields = ["First", "Surname", "Email", "Phone"]
                    Final_List: list = list()

                    if not all(Field in request.form for Field in Required_Fields):
                        return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error="Please fill out all required fields, marked with (*).")

                    for Field in Full_Fields:

                        if Field != "Fullname":

                            if Field != "Phone" and not Validator(String_to_Check=str(request.form.get(Field)), Safe_Characters=Standard_Safe_Chars):
                                return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error="Please ensure the fields do not contain any bad characters.")
                        
                            elif Field == "Phone" and not Common.Regex_Handler(str(request.form.get(Field)), Type="Phone_Multi"):
                                return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error="Please ensure the provided phone number only contains numbers and starts with a + symbol and country code, please remove any spaces.")
                            
                            elif Field == "Email" and not Common.Regex_Handler(str(request.form.get(Field)), Type="Email"):
                                return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error="Please ensure the provided email address is in the correct format.")
                        
                            elif Field not in ("Email", "Phone") and not Validator(String_to_Check=str(request.form.get(Field)), Safe_Characters=Restricted_Safe_Chars):
                                return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error="Please ensure the fields do not contain any bad characters.")

                            if Field in ["First", "Middle", "Surname"]:
                                Final_List.append(str(request.form.get(Field)).capitalize())
                            
                            else:
                                Final_List.append(str(request.form.get(Field)))

                        else:

                            if request.form.get("Middle"):
                                Full_Name = request.form.get("First").capitalize() + " " + request.form.get("Middle").capitalize() + " " + request.form.get("Surname").capitalize()

                            else:
                                Full_Name = request.form.get("First").capitalize() + " " + request.form.get("Surname").capitalize()

                            Final_List.append(Full_Name)

                    Cursor.execute('INSERT INTO org_identities (firstname, middlename, surname, fullname, username, email, phone) VALUES (%s,%s,%s,%s,%s,%s,%s)', tuple(Final_List))
                    Connection.commit()
                    Message = f"New identity created by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    time.sleep(1)
                    return redirect(url_for('identities'))
                    
                else:
                    return redirect(url_for('identities'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('identities'))

        @app.route('/api/identity/new')
        @csrf.exempt
        @api_auth_requirement
        @api_admin_requirement
        @RateLimiter(max_calls=API_Max_Calls, period=API_Period)
        def api_identities_new():

            try:

                if request.method == 'POST':

                    if request.is_json:
                        Content = request.get_json()
                        Full_Fields = ["First", "Middle", "Surname", "Fullname", "Username", "Email", "Phone"]
                        Required_Fields = ["First", "Surname", "Email", "Phone"]
                        Final_List: list = list()

                        if not all(Field in Content for Field in Required_Fields):
                            return jsonify({"Error": "Please fill out all required fields (" + ", ".join(Required_Fields) + ")."}), 500

                        for Field in Full_Fields:

                            if Field != "Fullname":

                                if Field != "Phone" and not Validator(String_to_Check=str(request.form.get(Field)), Safe_Characters=Standard_Safe_Chars):
                                    return jsonify({"Error": "Please ensure the fields do not contain any bad characters."}), 500

                                elif Field == "Phone" and not Common.Regex_Handler(str(Content.get(Field)), Type="Phone_Multi"):
                                    return jsonify({"Error": "Please ensure the provided phone number only contains numbers and starts with a + symbol and country code, please remove any spaces."}), 500
                                
                                elif Field == "Email" and not Common.Regex_Handler(str(Content.get(Field)), Type="Email"):
                                    return jsonify({"Error": "Please ensure the provided email address is in the correct format."}), 500
                            
                                elif Field not in ["Email", "Phone"] and not Validator(String_to_Check=str(request.form.get(Field)), Safe_Characters=Restricted_Safe_Chars):
                                    return jsonify({"Error": "Please ensure the fields do not contain any bad characters."}), 500

                                if Field in ["First", "Middle", "Surname"]:
                                    Final_List.append(str(Content.get(Field)).capitalize())
                                
                                else:
                                    Final_List.append(str(Content.get(Field)))

                            else:

                                if Content.get("Middle"):
                                    Full_Name = Content.get("First").capitalize() + " " + Content.get("Middle").capitalize() + " " + Content.get("Surname").capitalize()

                                else:
                                    Full_Name = Content.get("First").capitalize() + " " + Content.get("Surname").capitalize()

                                Final_List.append(Full_Name)

                        Cursor.execute('INSERT INTO org_identities (firstname, middlename, surname, fullname, username, email, phone) VALUES (%s,%s,%s,%s,%s,%s,%s)', tuple(Final_List))
                        Connection.commit()
                        Message = f"New identity created."
                        Create_Event(Message)
                        return jsonify({"Message": Message}), 200

                    else:
                        return jsonify({"Error": "Request is not in JSON format."}), 500

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        @app.route('/identities/upload', methods=['POST', 'GET'])
        @login_requirement
        @admin_requirement
        def bulk_identity_upload():

            try:

                if session.get('identities_form_step') == 0 or request.method == "GET":
                    session['identities_form_step'] = 1
                    session['identities_form_type']: str = "bulk"
                    return render_template('identities.html', username=session.get('user'),
                                            form_type=session.get('identities_form_type'),
                                            is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'))

                elif session.get('identities_form_step') == 1:
                    time.sleep(1)

                    if request.form.get("bulk_identities"):
                        Iterator = 1
                        Records_to_Insert: list = list()

                        for Identity_Row in request.form["bulk_identities"].split("\r\n"):
                            Attributes = Identity_Row.split(",")
                            Final_List: list = list()

                            if len(Attributes) == 6:
                                Required_Attributes = [Attributes[0], Attributes[2], Attributes[3], Attributes[5]]
                                Attr_Iterator: int = int()

                                for Attribute in Attributes:

                                    if Attribute in Required_Attributes and Attribute == str():
                                        return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error=f"Please ensure all required fields (marked with *) have a value provided. The offending line is line {str(Iterator)}.")

                                    elif Attribute != Attributes[5] and not Validator(String_to_Check=str(Attribute), Safe_Characters=Standard_Safe_Chars):
                                        return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error=f"Please ensure the fields do not contain any bad characters. The offending line is line {str(Iterator)}.")
                                
                                    elif Attribute == Attributes[5] and not Common.Regex_Handler(Attribute, Type="Phone_Multi"):
                                        return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error=f"Please ensure the provided phone number only contains numbers and starts with a + symbol and country code, please remove any spaces. The offending line is line {str(Iterator)}.")
                                    
                                    elif Attribute == Attributes[4] and not Common.Regex_Handler(Attribute, Type="Email"):
                                        return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error=f"Please ensure the provided email address is in the correct format. The offending line is line {str(Iterator)}.")
                                
                                    elif Attribute not in Attributes[-2:] and not Validator(String_to_Check=str(Attribute), Safe_Characters=Restricted_Safe_Chars):
                                        return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error=f"Please ensure the fields do not contain any bad characters. The offending line is line {str(Iterator)}.")

                                    if Attribute in Attributes[:3]:
                                        Final_List.append(Attribute.capitalize())
                                    
                                    else:
                                        Final_List.append(Attribute)

                                    if Attr_Iterator == 2:

                                        if Attributes[1] != str():
                                            Full_Name = Attributes[0].capitalize() + " " + Attributes[1].capitalize() + " " + Attributes[2].capitalize()

                                        else:
                                            Full_Name = Attributes[0].capitalize() + " " + Attributes[2].capitalize()

                                        Final_List.append(Full_Name)

                                    Attr_Iterator += 1

                                Records_to_Insert.append(tuple(Final_List))

                            else:
                                return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error=f"Please ensure none of the lines have missing fields. The offending line is line {str(Iterator)}.")
                        
                            Iterator += 1

                        if len(Records_to_Insert) > int():

                            for Record in Records_to_Insert:
                                Cursor.execute('INSERT INTO org_identities (firstname, middlename, surname, fullname, username, email, phone) VALUES (%s,%s,%s,%s,%s,%s,%s)', Record)
                        
                        Connection.commit()
                        Message = f"Bulk identities uploaded by {session.get('user')}."
                        app.logger.warning(Message)
                        Create_Event(Message)
                        time.sleep(1)
                        return redirect(url_for('identities'))
                    
                else:
                    return redirect(url_for('identities'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('identities'))

        @app.route('/identities/edit/<identity_id>', methods=['POST', 'GET'])
        @login_requirement
        @admin_requirement
        def edit_identity(identity_id):

            try:
                   
                if session.get('identities_form_step') == 0 or request.method == "GET":
                    session['identity_id'] = int(identity_id)
                    Cursor.execute("SELECT * FROM org_identities WHERE identity_id = %s;", (session.get('identity_id'),))
                    results = Cursor.fetchone()

                    if results:
                        session['identities_form_step'] = 1
                        session['identities_form_type']: str = "edit"
                        return render_template('identities.html', username=session.get('user'), form_step=session.get('identities_form_step'), form_type=session.get("identities_form_type"), is_admin=session.get('is_admin'), results=results)

                    else:
                        session['identities_message']: str = "Invalid value provided. Failed to edit object."
                        return redirect(url_for("identities"))

                elif session.get('identities_form_step') == 1:
                    time.sleep(1)
                    Cursor.execute("SELECT * FROM org_identities WHERE identity_id = %s;", (session.get('identity_id'),))
                    results = Cursor.fetchone()
                    Full_Fields = ["First", "Middle", "Surname", "Fullname", "Username", "Email", "Phone"]
                    Required_Fields = ["First", "Surname", "Email", "Phone"]
                    Final_List: list = list()

                    if not all(Field in request.form for Field in Required_Fields):
                        return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error="Please fill out all required fields, marked with (*).", results=results)

                    for Field in Full_Fields:

                        if Field != "Fullname":

                            if Field != "Phone" and not Validator(String_to_Check=str(request.form.get(Field)), Safe_Characters=Standard_Safe_Chars):
                                return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error="Please ensure the fields do not contain any bad characters.", results=results)
                        
                            elif Field == "Phone" and not Common.Regex_Handler(str(request.form.get(Field)), Type="Phone_Multi"):
                                return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error="Please ensure the provided phone number only contains numbers and starts with a + symbol and country code, please remove any spaces.", results=results)
                            
                            elif Field == "Email" and not Common.Regex_Handler(str(request.form.get(Field)), Type="Email"):
                                return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error="Please ensure the provided email address is in the correct format.", results=results)
                        
                            elif Field not in ["Email", "Phone"] and not Validator(String_to_Check=str(request.form.get(Field)), Safe_Characters=Restricted_Safe_Chars):
                                return render_template('identities.html', username=session.get('user'), form_type=session.get('identities_form_type'), is_admin=session.get('is_admin'), form_step=session.get('identities_form_step'), error="Please ensure the fields do not contain any bad characters.", results=results)

                            if Field in ["First", "Middle", "Surname"]:
                                Final_List.append(str(request.form.get(Field)).capitalize())
                            
                            else:
                                Final_List.append(str(request.form.get(Field)))

                        else:

                            if request.form.get("Middle"):
                                Full_Name = request.form.get("First").capitalize() + " " + request.form.get("Middle").capitalize() + " " + request.form.get("Surname").capitalize()

                            else:
                                Full_Name = request.form.get("First").capitalize() + " " + request.form.get("Surname").capitalize()

                            Final_List.append(Full_Name)

                    Final_List.append(session.get('identity_id'))
                    Cursor.execute('UPDATE org_identities SET firstname = %s, middlename = %s, surname = %s, fullname = %s, username = %s, email = %s, phone = %s WHERE identity_id = %s', tuple(Final_List))
                    Connection.commit()
                    Message = f"Identity ID {str(session.get('identity_id'))} updated by {session.get('user')}."
                    app.logger.warning(Message)
                    Create_Event(Message)
                    time.sleep(1)
                    return redirect(url_for('identities'))
                    
                else:
                    return redirect(url_for('identities'))

            except Exception as e:
                app.logger.error(e)
                return redirect(url_for('identities'))

        @app.route('/api/identity/edit/<identity_id>')
        @csrf.exempt
        @api_auth_requirement
        @api_admin_requirement
        def api_edit_identity(identity_id):

            try:

                if request.method == 'POST':

                    if request.is_json:
                        Content = request.get_json()
                        identity_id = str(int(identity_id))
                        Cursor.execute("SELECT * FROM org_identities WHERE identity_id = %s;", (identity_id,))
                        results = Cursor.fetchone()

                        if results:
                            Full_Fields = ["First", "Middle", "Surname", "Fullname", "Username", "Email", "Phone"]
                            Required_Fields = ["First", "Surname", "Email", "Phone"]
                            Final_List: list = list()

                            if not all(Field in Content for Field in Required_Fields):
                                return jsonify({"Error": "Please fill out all required fields (" + ", ".join(Required_Fields) + ")."}), 500

                            for Field in Full_Fields:

                                if Field != "Fullname":

                                    if Field != "Phone" and not Validator(String_to_Check=str(Content.get(Field)), Safe_Characters=Standard_Safe_Chars):
                                        return jsonify({"Error": "Please ensure the fields do not contain any bad characters."}), 500

                                    elif Field == "Phone" and not Common.Regex_Handler(str(Content.get(Field)), Type="Phone_Multi"):
                                        return jsonify({"Error": "Please ensure the provided phone number only contains numbers and starts with a + symbol and country code, please remove any spaces."}), 500
                                    
                                    elif Field == "Email" and not Common.Regex_Handler(str(Content.get(Field)), Type="Email"):
                                        return jsonify({"Error": "Please ensure the provided email address is in the correct format."}), 500
                                
                                    elif Field not in ["Email", "Phone"] and not Validator(String_to_Check=str(Content.get(Field)), Safe_Characters=Restricted_Safe_Chars):
                                        return jsonify({"Error": "Please ensure the fields do not contain any bad characters."}), 500

                                    if Field in ["First", "Middle", "Surname"]:
                                        Final_List.append(str(Content.get(Field)).capitalize())
                                    
                                    else:
                                        Final_List.append(str(Content.get(Field)))

                                else:

                                    if request.form.get("Middle"):
                                        Full_Name = Content.get("First").capitalize() + " " + Content.get("Middle").capitalize() + " " + Content.get("Surname").capitalize()

                                    else:
                                        Full_Name = Content.get("First").capitalize() + " " + Content.get("Surname").capitalize()

                                    Final_List.append(Full_Name)

                            Final_List.append(identity_id)
                            Cursor.execute('UPDATE org_identities SET firstname = %s, middlename = %s, surname = %s, fullname = %s, username = %s, email = %s, phone = %s WHERE identity_id = %s', tuple(Final_List))
                            Connection.commit()
                            Message = f"Identity ID {str(identity_id)} updated."
                            Create_Event(Message)
                            return jsonify({"Message": Message}), 200

                        else:
                            return jsonify({"Error": "Invalid reference."}), 500

                    else:
                        return jsonify({"Error": "Request is not in JSON format."}), 500

                else:
                    return jsonify({"Error": "Method not allowed."}), 500

            except Exception as e:
                app.logger.error(e)
                return jsonify({"Error": "Unknown error."}), 500

        Permit_Screenshots = General.Screenshot(File_Path, False).Screenshot_Checker()
        app.run(debug=Application_Details[0], host=Application_Details[1], port=Application_Details[2], threaded=True, ssl_context=context)

    except Exception as e:
        sys.exit(str(e))