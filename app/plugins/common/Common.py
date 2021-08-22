import json, os, datetime, urllib, requests, logging, re, csv, smtplib, slack, psycopg2
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from docx import Document
from jira.client import JIRA
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from defectdojo_api import defectdojo

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
Current_User_Agent = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'

class Configuration:

    def __init__(self, Input=False, Output=False, Core=False):

        try:
            self.key = ""

            if Input:
                self.key = "inputs"

            elif Output:
                self.key = "outputs"

            elif Core:
                self.key = "core"

            if self.key != "":
                JSON_File = open(Set_Configuration_File(), "r")
                Configuration_Data = JSON_Handler(JSON_File).To_JSON_Load()
                JSON_File.close()
                self.JSON_Data = Configuration_Data
                self.JSON_Object_Details = Configuration_Data[self.key]

            else:
                self.JSON_Object_Details = None

        except Exception as e:
            logging.warning(f"{Date()} - Common Library - Failed to load configuration file - {str(e)}.")

    def Load_Keys(self):

        try:

            if self.JSON_Object_Details:
                return list(self.JSON_Object_Details.keys())

            else:
                return None

        except Exception as e:
            logging.warning(f"{Date()} - Common Library - Failed to load keys for section {self.key} - {str(e)}.")

    def Load_Values(self, Object=""):

        try:

            if self.JSON_Object_Details and Object != "":
                return self.JSON_Object_Details[Object]

            else:
                return None

        except Exception as e:
            logging.warning(f"{Date()} - Common Library - Failed to load object data - {str(e)}.")

    def Set_Field(self, Object="", Config={}):

        try:

            if self.JSON_Object_Details and Object != "" and Config != {} and Object in self.JSON_Data[self.key]:
                self.JSON_Data[self.key][Object] = Config
                JSON_File = open(Set_Configuration_File(), "w")
                JSON_File.write(JSON_Handler(self.JSON_Data).Dump_JSON(Sort=False))
                JSON_File.close()
                return True

        except Exception as e:
            logging.warning(f"{Date()} - Common Library - Failed to set field - {str(e)}.")  

    def Load_Configuration(self, Location=False, Postgres_Database=False, Object="", Details_to_Load=[]):

        try:

            if Postgres_Database:
                Details_to_Load = ["host", "port", "user", "password", "database"]

            if self.JSON_Object_Details:
                
                if Object in self.JSON_Object_Details:
                    Return_Details = []

                    for Detail in Details_to_Load:
                        Current_Item = self.JSON_Object_Details[Object]

                        if Detail in Current_Item:
                            Current_Item = Current_Item[Detail]
                            Return_Details.append(Current_Item)

                        else:
                            return None

                    if not Location and not Postgres_Database:

                        if len(Return_Details) > 1:
                            return Return_Details

                        elif len(Return_Details) == 1:
                            return Return_Details[0]

                        else:
                            return None

                    elif Location and not Postgres_Database:
                        Result_Detail = Return_Details[0]
                        Valid_Locations = ['ac', 'ac', 'ad', 'ae', 'af', 'af', 'ag', 'ag', 'ai', 'al', 'am', 'am', 'ao', 'aq', 'ar', 'as', 'at', 'au', 'az', 'ba', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bi', 'bj', 'bn', 'bo', 'bo', 'br', 'bs', 'bt', 'bw', 'by', 'by', 'bz', 'ca', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'cn', 'co', 'co', 'co', 'cr', 'cu', 'cv', 'cy', 'cz', 'de', 'dj', 'dk', 'dm', 'do', 'dz', 'ec', 'ec', 'ee', 'eg', 'es', 'et', 'eu', 'fi', 'fj', 'fm', 'fr', 'ga', 'ge', 'ge', 'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gp', 'gp', 'gr', 'gr', 'gt', 'gy', 'gy', 'gy', 'hk', 'hk', 'hn', 'hr', 'ht', 'ht', 'hu', 'hu', 'id', 'id', 'ie', 'il', 'im', 'im', 'in', 'in', 'io', 'iq', 'iq', 'is', 'it', 'je', 'je', 'jm', 'jo', 'jo', 'jp', 'jp', 'ke', 'kg', 'kh', 'ki', 'kr', 'kw', 'kz', 'kz', 'la', 'lb', 'lc', 'li', 'lk', 'ls', 'lt', 'lu', 'lv', 'ly', 'ma', 'ma', 'md', 'me', 'mg', 'mk', 'ml', 'mm', 'mn', 'ms', 'mt', 'mu', 'mv', 'mw', 'mx', 'mx', 'my', 'mz', 'na', 'ne', 'nf', 'ng', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nr', 'nu', 'nz', 'om', 'pa', 'pe', 'pe', 'pf', 'pg', 'ph', 'pk', 'pk', 'pl', 'pl', 'pn', 'pr', 'ps', 'ps', 'pt', 'py', 'qa', 'qa', 're', 'ro', 'rs', 'rs', 'ru', 'ru', 'rw', 'sa', 'sb', 'sc', 'se', 'sg', 'sh', 'si', 'sk', 'sl', 'sl', 'sm', 'sn', 'so', 'sr', 'st', 'sv', 'sy', 'td', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tt', 'tz', 'ua', 'ua', 'ug', 'uk', 'us', 'us', 'uy', 'uz', 'uz', 'vc', 've', 've', 'vg', 'vi', 'vn', 'vu', 'ws', 'za', 'zm', 'zw']

                        if Result_Detail not in Valid_Locations:
                            logging.warning(f"{Date()} - Common Library - An invalid location has been specified, please provide a valid location in the config.json file.")

                        else:
                            logging.info(f"{Date()} - Common Library - Country code {Result_Detail} selected.")
                            return Result_Detail

                    else:

                        try:
                            DB_Connection = psycopg2.connect(user=Return_Details[2],
                                          password=Return_Details[3],
                                          host=Return_Details[0],
                                          port=int(Return_Details[1]),
                                          database=Return_Details[4])

                            if DB_Connection:
                                return DB_Connection

                            else:
                                return None

                        except:
                            logging.warning(f"{Date()} - Common Library - Failed to connect to database.")
                            return None

                else:
                    return None

            else:
                return None

        except Exception as e:
            logging.warning(f"{Date()} - Common Library - Failed to load details for object {str(Object)} - {str(e)}.")

def CSV_Output(Object, Title, Plugin_Name, Domain, Link, Result_Type, Output_File, Task_ID, Directory):

    try:
        Use_CSV = Load_Output(Object, "csv")

        if Use_CSV:
            File_Dir = os.path.dirname(os.path.realpath('__file__'))
            Headings = ["Title", "Plugin", "Domain", "Link", "Created At", "Output Files", "Result Type", "Task ID"]
            Data = [Title, Plugin_Name, Domain, Link, Date(), Output_File, Result_Type, str(Task_ID)]
            Complete_File = f"{File_Dir}/static/protected/output/{Directory}/{Plugin_Name}-Output.csv"

            if not os.path.exists(Complete_File):
                CSV_Output = csv.writer(open(Complete_File, 'w'))
                CSV_Output.writerow(Headings)
                CSV_Output.writerow(Data)
                logging.info(f"{Date()} - Common Library - Created new CSV file located at {str(Complete_File)}.")

            else:
                CSV_Output = csv.writer(open(Complete_File, 'a'))
                CSV_Output.writerow(Data)
                logging.info(f"{Date()} - Common Library - Updated existing CSV file located at {str(Complete_File)}.")

            return Complete_File

        else:
            return None

    except Exception as e:
        logging.warning(f"{Date()} - Common Library - {str(e)}.")

def DOCX_Output(Object, Title, Plugin_Name, Domain, Link, Result_Type, Output_File, Task_ID, Directory):

    try:
        Use_DOCX = Load_Output(Object, "docx")

        if Use_DOCX:
            File_Dir = os.path.dirname(os.path.realpath('__file__'))
            Complete_File = f"{File_Dir}/static/protected/output/{Directory}/{Plugin_Name}-Output.docx"

            if os.path.exists(Complete_File):
                document = Document(Complete_File)

            else:
                from docx.shared import Inches
                from docx.enum.text import WD_ALIGN_PARAGRAPH
                document = Document()
                h1 = document.add_heading(f'Scrummage Finding Report for {Plugin_Name} Plugin', 0)
                h1.alignment = WD_ALIGN_PARAGRAPH.CENTER
                image = document.add_picture(f"{File_Dir}/static/images/search.png", width=Inches(2.00))
                last_paragraph = document.paragraphs[-1]
                last_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                document.add_page_break()

            Document_Data = (
                ('Plugin', Plugin_Name),
                ('Domain', Domain),
                ('Link', Link),
                ('Created At', str(Date())),
                ('Result Type', Result_Type),
                ('Output Files', Output_File),
                ('Associated Task ID', str(Task_ID))
            )

            table = document.add_table(rows=1, cols=2)
            hdr_cells = table.rows[0].cells
            hdr_cells[0].text = 'Title'
            hdr_cells[1].text = Title

            for name, data in Document_Data:
                row_cells = table.add_row().cells
                row_cells[0].text = name
                row_cells[1].text = data

            document.add_page_break()
            document.save(Complete_File)
            logging.info(f"{Date()} - Common Library - Exported to DOCX file located at {str(Complete_File)}.")
            return Complete_File

        else:
            return None

    except Exception as e:
        logging.warning(f"{Date()} - Common Library - {str(e)}.")

def Load_Output(Object, Type):

    if Type == "docx":
        return Object.Load_Configuration(Object="docx_report", Details_to_Load=["use_docx"])

    elif Type == "csv":
        return Object.Load_Configuration(Object=Type, Details_to_Load=["use_csv"])

    elif Type == "defectdojo":
        return Object.Load_Configuration(Object=Type, Details_to_Load=["ssl", "api_key", "host", "user", "engagement_id", "product_id", "test_id", "user_id"])

    elif Type == "postgresql":
        return Object.Load_Configuration(Postgres_Database=True, Object=Type)

    elif Type == "scumblr":
        return Object.Load_Configuration(Postgres_Database=True, Object=Type)

    elif Type == "rtir":
        return Object.Load_Configuration(Object=Type, Details_to_Load=["ssl", "host", "port", "user", "password", "authenticator"])

    elif Type == "jira":
        return Object.Load_Configuration(Object=Type, Details_to_Load=["project_key", "address", "username", "password", "ticket_type"])

    elif Type == "slack":
        return Object.Load_Configuration(Object=Type, Details_to_Load=["token", "channel"])

    elif Type == "elasticsearch":
        return Object.Load_Configuration(Object=Type, Details_to_Load=["ssl", "host", "port", "index", "use_timestamp"])

    elif Type == "email":
        return Object.Load_Configuration(Object=Type, Details_to_Load=["smtp_server", "smtp_port", "from_address", "from_password", "to_address"])

def Defect_Dojo_Output(Object, Title, Description):
    DD_Details = Load_Output(Object, "defectdojo")

    if DD_Details:

        try:

            if DD_Details[0]:
                Service = "https://"

            else:
                Service = "http://"

            Host = Service + DD_Details[2]
            Impact = 'All Scrummage findings have the potential to cause significant damage to a business\' finances, efficiency and reputation. Therefore, findings should be investigated to assist in reducing this risk.'
            Mitigation = 'It is recommended that this issue be investigated further by the security team to determine whether or not further action needs to be taken.'
            DD_Connection = defectdojo.DefectDojoAPI(Host, DD_Details[1], DD_Details[3], debug=False)
            Finding = DD_Connection.create_finding(Title, Description, 'Low', '', str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d')), DD_Details[5], DD_Details[4], DD_Details[6], DD_Details[7], Impact, True, False, Mitigation)

            try:
                Finding = str(int(str(Finding)))
                logging.info(f"{Date()} - Common Library - DefectDojo finding {Finding} created.")

            except:
                logging.info(f"{Date()} - Common Library - Failed to create DefectDojo finding.")

        except (Exception, psycopg2.DatabaseError) as Error:
            logging.warning(Date() + str(Error))

def Main_Database_Insert(Object, Title, Plugin_Name, Domain, Link, Result_Type, Output_File, Task_ID, Screenshot_Path=False):
    Connection = Load_Output(Object, "postgresql")
    logging.info(f"{Date()} - Common Library - Loading Scrummage's Main Database configuration data.")

    if Connection:

        try:
            # Create connection cursor.
            Cursor = Connection.cursor()
            Cursor.execute("SELECT * FROM results WHERE link like %s", (Link,))
            Item_Already_in_Database = Cursor.fetchone()

            if Item_Already_in_Database is None:
                # Execute statement.

                if not Screenshot_Path:
                    Cursor.execute("INSERT INTO results (title, plugin, status, domain, link, created_at, updated_at, output_file, result_type, task_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (Title, Plugin_Name, "Open", Domain, Link, Date(), Date(), Output_File, Result_Type, Task_ID,))

                else:
                    Cursor.execute("INSERT INTO results (title, plugin, status, domain, link, created_at, updated_at, output_file, result_type, task_id, screenshot_url) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (Title, Plugin_Name, "Open", Domain, Link, Date(), Date(), Output_File, Result_Type, Task_ID, Screenshot_Path,))

            else:
                logging.info(f"{Date()} - Common Library - Entry already exists in the database. Skipping...")

        except (Exception, psycopg2.DatabaseError) as Error:
            logging.warning(Date() + str(Error))

        finally:

            if Connection is not None:
                Connection.commit()
                Connection.close()
                logging.info(f"{Date()} - Common Library - Result added to Scrummage database.")

def Scumblr_Main(Object, Link, Domain, Title):
    Connection = Load_Output(Object, "scumblr")

    if Connection:

        try:
            # Create connection cursor.
            Cursor = Connection.cursor()
            Cursor.execute("SELECT * FROM results WHERE url like %s", (Link,))
            Item_Already_in_Database = Cursor.fetchone()

            if Item_Already_in_Database is None:
                # Execute statement.
                Cursor.execute("INSERT INTO results (title, url, created_at, updated_at, domain) VALUES(%s, %s, %s, %s, %s)", (Title, Link, Date(), Date(), Domain))

            else:
                logging.info(f"{Date()} - Common Library - Entry already exists in Scumblr database. Skipping...")

        except (Exception, psycopg2.DatabaseError) as Error:
            logging.warning(f"{Date()} - Common Library - " + Error)

        finally:

            if Connection is not None:
                Connection.commit()
                Connection.close()
                logging.info(f"{Date()} - Common Library - Result added to Scumblr database.")

def RTIR_Main(Object, Ticket_Subject, Ticket_Text):
    RTIR_Details = Load_Output(Object, "rtir")

    if RTIR_Details:

        try:

            if RTIR_Details[0]:
                Service = "https://"

            else:
                Service = "http://"

            Request_Data = f"content=id: ticket/new\nQueue: 1\nSubject: {Ticket_Subject}\nText: {Ticket_Text}"

            if RTIR_Details[5] != "cookie_based":
                logging.info(f"{Date()} - Common Library - No Authenticator specified, using the default which is cookie-based authentication.")

            RTIR_Response = Request_Handler(f"{Service}://{RTIR_Details[1]}:{RTIR_Details[2]}/REST/1.0/ticket/new?user={RTIR_Details[3]}&pass={RTIR_Details[4]}", Method="POST", Data=Request_Data)

            if RTIR_Response.status_code == 200:
                logging.info(f"{Date()} - Common Library - New RTIR ticket created.")

            else:
                logging.warning(f"{Date()} - Common Library - Failed to create ticket in RTIR.")

        except Exception as e:
            logging.warning(f"{Date()} - Common Library - {str(e)}.")

def JIRA_Main(Object, Ticket_Summary, Ticket_Description):
    JIRA_Details = Load_Output(Object, "jira")

    if JIRA_Details:

        try:
            JIRA_Options={'server': JIRA_Details[1]}
            JIRA_Session=JIRA(options=JIRA_Options,basic_auth=(JIRA_Details[2], JIRA_Details[3]))
            JIRA_Session.create_issue(project={'key': JIRA_Details[0]}, summary=Ticket_Summary, description=Ticket_Description, issuetype={'name': JIRA_Details[4]})
            logging.info(f"{Date()} - Common Library - New JIRA ticket created.")

        except Exception as e:
            logging.warning(f"{Date()} - Common Library - {str(e)}.")

def Slack_Main(Object, Description):
    Slack_Details = Load_Output(Object, "slack")

    if Slack_Details:

        try:
            client = slack.WebClient(token=Slack_Details[0])
            client.chat_postMessage(channel=Slack_Details[1], text=Description)
            logging.info(f"{Date()} - Common Library - New Slack Notification created.")

        except Exception as e:
            logging.warning(f"{Date()} - Common Library - {str(e)}.")

def Elasticsearch_Main(Object, Title, Plugin_Name, Domain, Link, Result_Type, Output_File, Task_ID, Concat_Plugin_Name):
    Elasticsearch_Details = Load_Output(Object, "elasticsearch")

    if Elasticsearch_Details:

        try:

            if Elasticsearch_Details[4]:
                Timestamp = Date(Just_Date=True, Elastic=True)
                Index = Elasticsearch_Details[3] + "-" + Concat_Plugin_Name + "-" + Timestamp

            else:
                Index = Elasticsearch_Details[3] + "-" + Concat_Plugin_Name

            if Elasticsearch_Details[0]:
                Service = "https://"

            else:
                Service = "http://"

            URI = Service + Elasticsearch_Details[1] + ":" + str(Elasticsearch_Details[2]) + Index
            data = {"title": Title, "plugin": Plugin_Name, "domain": Domain, "link": Link, "output_file": Output_File, "result_type": Result_Type, "created_at": Date(), "associated_task_id": str(Task_ID)}
            data = JSON_Handler(data).Dump_JSON()
            resp = Request_Handler(URI, Method="POST", Application_JSON_CT=True, Full_Response=True, Data=data)

            if resp.status_code == 200:
                logging.info(f"{Date()} - Common Library - New result created in Elasticsearch, using the URI {URI}.")

            else:
                logging.info(f"{Date()} - Common Library - Failed to create result in Elasticsearch, using the URI {URI}.")

        except:
            logging.warning(f"{Date()} - Common Library - Failed to create result in Elasticsearch.")

def Email_Main(Object, Email_Subject, Email_Body):
    Email_Details = Load_Output(Object, "email")

    if Email_Details:

        try: # Send Email Alerts when called.
            server = smtplib.SMTP(Email_Details[0], Email_Details[1])
            server.ehlo()
            server.starttls()
            server.login(Email_Details[2], Email_Details[3])
            msg = MIMEMultipart()
            msg['From'] = Email_Details[2]
            msg['To'] = Email_Details[4]
            msg['Subject'] = Email_Subject
            msg.attach(MIMEText(Email_Body, 'plain'))
            text = msg.as_string()
            server.sendmail(Email_Details[2], Email_Details[4], text)
            server.quit()
            logging.info(f"{Date()} - Common Library - Email Sent.")

        except:
            logging.warning(f"{Date()} - Common Library - Failed to send alert! Check email login settings.")

def Set_Configuration_File():

    try:
        File_Dir = os.path.dirname(os.path.realpath('__file__'))
        return os.path.join(File_Dir, 'plugins/common/config/config.json')

    except Exception as e:
        logging.warning(f"DATE FUNCTION ERROR - Common Library - {str(e)}.")

def Date(Additional_Last_Days=0, Date_Only=False, Elastic=False, Full_Timestamp=False):

    try:

        def Date_Handler(Timestamp, Date_Only_Inner, Elastic_Inner):

            if Date_Only_Inner and not Elastic_Inner:
                return str(Timestamp.strftime('%Y-%m-%d'))

            elif Date_Only_Inner and Elastic_Inner:
                return str(Timestamp.strftime('%Y.%m.%d'))

            else:
                return str(Timestamp.strftime('%Y-%m-%d %H:%M:%S'))

        if Additional_Last_Days > 0:
            Additional_Last_Days_Range = Additional_Last_Days - 1
            Real_Dates = []

            while Additional_Last_Days_Range < Additional_Last_Days and Additional_Last_Days_Range >= 0:
                Today = datetime.datetime.now()
                Day = datetime.timedelta(days=Additional_Last_Days_Range)
                Real_Date = Today - Day
                Real_Date = Date_Handler(Real_Date, Date_Only, Elastic)
                Real_Dates.append(Real_Date)
                Additional_Last_Days_Range -= 1

            return Real_Dates

        if Full_Timestamp:
            return datetime.datetime.now()

        else:
            return Date_Handler(datetime.datetime.now(), Date_Only, Elastic)

    except Exception as e:
        logging.warning(f"DATE FUNCTION ERROR - Common Library - {str(e)}.")

class JSON_Handler:

    def __init__(self, raw_data):
        self.json_data = raw_data

    def Is_JSON(self):

        try:
            json_object = json.loads(self.json_data)

        except ValueError as e:
            return False

        return json_object

    def To_JSON_Load(self):

        try:
            self.json_data = json.load(self.json_data)
            return self.json_data

        except Exception as e:
            logging.error(f"{Date()} - Common Library - {str(e)}.") 

    def To_JSON_Loads(self):

        try:
            self.json_data = json.loads(self.json_data)
            return self.json_data

        except Exception as e:
            logging.error(f"{Date()} - Common Library - {str(e)}.")   

    def Dump_JSON(self, Indentation=2, Sort=True):

        try:

            if Indentation > 0:
                self.json_data = json.dumps(self.json_data, indent=Indentation, sort_keys=Sort)

            else:
                self.json_data = json.dumps(self.json_data, sort_keys=Sort)

            return self.json_data

        except Exception as e:
            logging.error(f"{Date()} - Common Library - {str(e)}.")

def Request_Handler(URL, Method="GET", User_Agent=True, Application_JSON_CT=False, Application_Form_CT=False, Accept_XML=False, Accept_Language_EN_US=False, Filter=False, Risky_Plugin=False, Full_Response=False, Host="", Data={}, Params={}, JSON_Data={}, Optional_Headers={}, Scrape_Regex_URL="", Proxies={}, Certificate_Verification=True):

    try:
        Headers = {}

        if type(Data) == dict or type(Data) == str:
            Result =  Configuration(Core=True).Load_Configuration(Object="proxy", Details_to_Load=["http", "https", "use_system_proxy"])

            if Result:
                
                if Result[2]:
                    Proxies = urllib.request.getproxies()

                elif Result[0] != "" and Result[1] != "":
                    Proxies = {"http": Result[0], "https": Result[1]}

            if User_Agent:
                Headers['User-Agent'] = Current_User_Agent

            if Application_JSON_CT:
                Headers['Content-Type'] = 'application/json'

            if Accept_XML:
                Headers['Accept'] = 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'

            if Accept_Language_EN_US:
                Headers['Accept-Language'] = 'en-US,en;q=0.5'

            if Application_Form_CT:
                Headers['Content-Type'] = 'application/x-www-form-urlencoded'

            if type(Optional_Headers) == dict and len(Optional_Headers) > 0:

                for Header_Key, Header_Value in Optional_Headers.items():
                    Headers[Header_Key] = Header_Value
                    
            try:
            
                if Method == "GET":

                    if Data:
                        Response = requests.get(URL, headers=Headers, data=Data, proxies=Proxies, verify=Certificate_Verification)

                    elif JSON_Data:
                        Response = requests.get(URL, headers=Headers, json=JSON_Data, proxies=Proxies, verify=Certificate_Verification)

                    elif Params:
                        Response = requests.get(URL, headers=Headers, params=Params, proxies=Proxies, verify=Certificate_Verification)

                    else:
                        Response = requests.get(URL, headers=Headers, proxies=Proxies, verify=Certificate_Verification)

                elif Method == "POST":

                    if Data:
                        Response = requests.post(URL, headers=Headers, data=Data, proxies=Proxies, verify=Certificate_Verification)

                    elif JSON_Data:
                        Response = requests.post(URL, headers=Headers, json=JSON_Data, proxies=Proxies, verify=Certificate_Verification)

                    elif Params:
                        Response = requests.post(URL, headers=Headers, params=Params, proxies=Proxies, verify=Certificate_Verification)

                    else:
                        Response = requests.post(URL, headers=Headers, proxies=Proxies, verify=Certificate_Verification)

                else:
                    logging.warning(f"{Date()} - Common Library - The supplied method is not supported.")
                    return None
                    
            except requests.exceptions.ConnectionError:
                return None

            if not Full_Response:
                Response = Response.text

            Response_Dict = {}

            if Scrape_Regex_URL != "":
                Scrape_URLs = []

                try:
                    Scrape_URLs_Raw = Regex_Handler(str(Response), Custom_Regex=Scrape_Regex_URL, Findall=True)

                    for Temp_URL_Extensions in Scrape_URLs_Raw:

                        if not Temp_URL_Extensions in Scrape_URLs:
                            Scrape_URLs.append(Temp_URL_Extensions)

                except:
                    logging.warning(f"{Date()} - Common Library - Failed to regex URLs.")

                Response_Dict["Regular"] = Response
                Response_Dict["Scraped"] = Scrape_URLs

            if Filter and str(Host) != "":
                Filtered_Response = Response_Filter(Response, str(Host), Risky_Plugin=Risky_Plugin)

                if not Response_Dict.get("Regular"):
                    Response_Dict["Regular"] = Response

                Response_Dict["Filtered"] = Filtered_Response

            if Response_Dict != {}:
                return Response_Dict

            else:
                return Response

        else:
            logging.warning(f"{Date()} - Common Library - The data field needs to be in a dictionary or string format.")

    except Exception as e:
        logging.warning(f"{Date()} - Common Library - {str(e)}.")

def Response_Filter(Response, Host, Risky_Plugin=False):
    Risk_Level = Configuration(Core=True).Load_Configuration(Object="web_scraping", Details_to_Load=["risk_level", "automated_screenshots"])
    Risk_Level = Risk_Level[0]

    if (Risk_Level == 3) or (Risk_Level == 2 and not Risky_Plugin):
        Attributes = ["src", "href"]
        Quotes = ["\"", "\'"]
        Replace_Items = ["/", "./"]
        Replace_Strings = ["js", "assets", "polyfills", "main", "styles", "css", "jquery", "img", "images", "atom", "?", "static", "logo", "gui"]

        for Attribute in Attributes:

            for Quote in Quotes:
                Response = Response.replace(f"{Attribute} = {Quote}", f"{Attribute}={Quote}")

                if "https://" in Host:
                    Response = Response.replace(f"{Attribute}={Quote}//", f"{Attribute}={Quote}https://")

                else:
                    Response = Response.replace(f"{Attribute}={Quote}//", f"{Attribute}={Quote}http://")

                for Replace_Item in Replace_Items:
                    Response = Response.replace(f"{Attribute}={Quote}{Replace_Item}", f"{Attribute}={Quote}{Host}/")

                for Replace_String in Replace_Strings:
                    Response = Response.replace(f"{Attribute}={Quote}{Replace_String}", f"{Attribute}={Quote}{Host}/{Replace_String}")

                Response = Response.replace(f"{Attribute}={Quote}{Host}//", f"{Attribute}={Quote}{Host}/")
        
    return Response

def Regex_Handler(Query, Type="", Custom_Regex="", Findall=False, Get_URL_Components=False):

    try:

        if Type != "":
            Predefined_Regex_Patterns = {"Phone": r"^\+\d+$", "Phone_Multi": r"^(\+)?\d+$", "Email": r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-\.]+$)", "Domain": r"([-a-zA-Z0-9@:%_\+~#=]{2,256}\.[a-z]{2,3})(\.[a-z]{2,3})?(\.[a-z]{2,3})?", "IP": r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "URL": r"^(https?\:\/\/(www\.)?)?([-a-zA-Z0-9@:%_\+\-~#=]{2,256})(\.[a-z]{2,3})(\.[a-z]{2,3})?(\.[a-z]{2,3})?$", "MD5": r"([a-fA-F0-9]{32})\W", "SHA1": r"([a-fA-F0-9]{40})\W", "SHA256": r"([a-fA-F0-9]{64})\W", "Credentials": r"[\w\d\.\-\_]+\@[\w\.]+\:.*", "Cron": r"^([\d\/\*\-\,]+)\s([\d\/\*\-\,]+)\s([\d\/\*\-\,]+)\s([\d\/\*\-\,]+)\s([\d\/\*\-\,]+)$", "File_Date": r".+\/\d{4}\/\d{2}\/\d{2}\/.+", "Password_Special_Characters": r"[\@\_\-\!\#\$\%\^\&\*\(\)\~\`\<\>\]\[\}\{\|\:\;\'\"\/\?\.\,\+\=]+", "Company_Name": r".*[a-zA-Z].*"}

            for Key, Value in Predefined_Regex_Patterns.items():

                if Type == Key:

                    if not Findall:
                        Regex = re.search(Value, Query)

                    else:
                        Regex = re.findall(Value, Query)

            if Regex and not Get_URL_Components:
                return Regex

            elif Regex and Type == "URL" and Get_URL_Components:
                URL_Prefix = Regex.group(1)
                URL_Body = Regex.group(3)

                if Regex.group(5) and Regex.group(6):
                    URL_Extension = Regex.group(4) + Regex.group(5) + Regex.group(6)

                elif Regex.group(5):
                    URL_Extension = Regex.group(4) + Regex.group(5)

                else:
                    URL_Extension = Regex.group(4)

                return {"Prefix": URL_Prefix, "Body": URL_Body, "Extension": URL_Extension}

            else:
                return None

        elif Custom_Regex != "":

            if not Findall:
                Regex = re.search(Custom_Regex, Query)

            else:
                Regex = re.findall(Custom_Regex, Query)

            if Regex:
                return Regex

            else:
                return None

        else:
            return None

    except Exception as e:
        logging.warning(f"{Date()} - Common Library - Failed to get check against a regex pattern. {str(e)}.")

def Filter(Segment_List, Start_Number, End_Number):

    try:

        def Dash_to_Numbers(Segment):
            List_of_Numbers = []
            Segments = Segment.split("-")
            Iterator = int(Segments[0])

            while Iterator <= int(Segments[1]):
                List_of_Numbers.append(str(Iterator))
                Iterator += 1

            return List_of_Numbers

        Segment_List_Filtered = []

        for Segment_Item in Segment_List:

            if "-" in Segment_Item:
                Segment_Item = Dash_to_Numbers(Segment_Item)
                Segment_List_Filtered.extend(Segment_Item)

            else:
                Segment_List_Filtered.append(Segment_Item)

        Non_Hardcoded_Segment_List = []
        Updated_Segment_List = []
        Iterator = 0
        Range_End = End_Number + 1
        Approved_Hours = list(range(Start_Number, Range_End))

        while Iterator < len(Segment_List_Filtered):
            Segment_Item = Segment_List_Filtered[Iterator]

            if Segment_Item != Segment_List_Filtered[-1] and "/" not in Segment_Item:
                Seg_Iter = 1
                First_Segment = Segment_Item
                Current_Segment = Segment_Item

                if (Iterator + Seg_Iter) < len(Segment_List_Filtered):
                    Current_Next_Value = Segment_List_Filtered[Iterator + Seg_Iter]
                    
                    while all(Seg.isnumeric() for Seg in [Current_Next_Value, Current_Segment]) and int(Current_Next_Value) in Approved_Hours and ((int(Current_Next_Value) - int(Current_Segment)) == 1):
                        Current_Segment = Current_Next_Value
                        Seg_Iter += 1
                        Curr_Iter = Iterator + Seg_Iter

                        if (Iterator + Seg_Iter) < len(Segment_List_Filtered):
                            Current_Next_Value = Segment_List_Filtered[Curr_Iter]

                        else:
                            break

                    if int(First_Segment) == End_Number:
                        Updated_Segment_List.append(First_Segment)

                    else:
                        Updated_Segment_List.append(First_Segment + "-" + Current_Segment)

                    Iterator += Seg_Iter

            elif "/" in Segment_Item:
                Non_Hardcoded_Segment_List.append(Segment_Item)
                Iterator += 1
            
            else:
                Iterator += 1

        if f"{str(Start_Number)}-{str(End_Number)}" in Updated_Segment_List:
            return ["*"]

        else:
            Updated_Segment_List.extend(Non_Hardcoded_Segment_List)
            return Updated_Segment_List

    except Exception as e:
        logging.warning(f"{Date()} - Common Library - Failed to verify and filter provided cron schedule. {str(e)}.")