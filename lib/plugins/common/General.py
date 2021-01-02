#!/usr/bin/env python3

import datetime, time, os, logging, re, requests, urllib, json, plugins.common.Connectors as Connectors
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
Bad_Characters = ["|", "/", "&", "?", "\\", "\"", "\'", "[", "]", ">", "<", "~", "`", ";", "{", "}", "%", "^"]
Current_User_Agent = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'

class Screenshot:

    def __init__(self, File_Path, Internally_Requested, **kwargs):
        self.Internally_Requested = Internally_Requested
        self.Chrome_Config = Connectors.Load_Chrome_Configuration()
        self.File_Path = File_Path
        self.Connection = Connectors.Load_Main_Database()
        self.Cursor = self.Connection.cursor()

        if not self.Internally_Requested and kwargs.get('Screenshot_ID') and kwargs.get('Screenshot_User'):
            self.Screenshot_ID = kwargs['Screenshot_ID']
            self.Screenshot_User = kwargs['Screenshot_User']

        elif self.Internally_Requested and kwargs.get('Screenshot_Link'):
            self.Screenshot_ID = False
            self.Screenshot_User = False
            self.Screenshot_Link = kwargs['Screenshot_Link']

    def Screenshot_Checker(self):

        if all(os.path.exists(Config) for Config in self.Chrome_Config): 
            CHROME_PATH = self.Chrome_Config[0]
            CHROMEDRIVER_PATH = self.Chrome_Config[1]
            Chrome_Options = Options()
            Chrome_Options.add_argument("--headless")
            Chrome_Options.binary_location = CHROME_PATH

            try:
                driver = webdriver.Chrome(
                    executable_path=CHROMEDRIVER_PATH,
                    options=Chrome_Options
                )
                return True

            except Exception as e:
                print(e)

                if "session not created" in str(e):
                    app.logger.warning(f"\033[0;31mPlease run the \"Fix_ChromeDriver.sh\" script in the installation directory to upgrade the Google Chrome Driver to be in-line with the current version of Google Chrome on this operating system, or replace it manually with the latest version from http://chromedriver.chromium.org/downloads that matches the version of Chrome installed on your system. The Chrome driver is located at {Chrome_Config[1]}. Screenshot functionality has been disabled in the meantime until this issue is resolved.\033[0m\n")
                    return False

        else:
            app.logger.warning("\033[0;31mOne or more of the values provided to the google chrome configuration in the config.json file do not reflect real files. Screenshot functionality has been disabled in the meantime. To correct this please accurately fill out the following section in the config.json file (Example values included, please ensure these reflect real files on your system)\n\n    \"google-chrome\": {\n        \"application-path\": \"/usr/bin/google-chrome\",\n        \"chromedriver-path\": \"/usr/bin/chromedriver\"\n    },\n\033[0m")
            return False

    def Grab_Screenshot(self):

        try:
            Bad_Link_Strings = ['.onion', 'general-insurance.coles.com.au', 'magnet:?xt=urn:btih:']

            if not self.Internally_Requested:
                self.Cursor.execute('SELECT link FROM results WHERE result_id = %s', (self.Screenshot_ID,))
                Result = self.Cursor.fetchone()
                self.Screenshot_Link = Result[0]
                Message = f"Screenshot requested for result number {str(self.Screenshot_ID)} by {self.Screenshot_User}."
                logging.warning(Message)
                self.Create_Event(Message)
                self.Cursor.execute('UPDATE results SET screenshot_requested = %s WHERE result_id = %s', (True, self.Screenshot_ID,))
                self.Connection.commit()

            if any(String in self.Screenshot_Link for String in Bad_Link_Strings):
                return None

            Screenshot_File = self.Screenshot_Link.replace("http://", "")
            Screenshot_File = Screenshot_File.replace("https://", "")

            if Screenshot_File.endswith('/'):
                Screenshot_File = Screenshot_File[:-1]

            if '?' in Screenshot_File:
                Screenshot_File_List = Screenshot_File.split('?')
                Screenshot_File = Screenshot_File_List[0]

            for Replaceable_Item in ['/', '?', '#', '&', '%', '$', '@', '*', '=']:
                Screenshot_File = Screenshot_File.replace(Replaceable_Item, '-')

            CHROME_PATH = self.Chrome_Config[0]
            CHROMEDRIVER_PATH = self.Chrome_Config[1]
            Screenshot_File = f"{Screenshot_File}.png"
            Chrome_Options = Options()
            Chrome_Options.add_argument("--headless")
            Chrome_Options.binary_location = CHROME_PATH

        except Exception as e:
            logging.warning(f"{Date()} General Library - {str(e)}.")

        try:
            Driver = webdriver.Chrome(
                executable_path=CHROMEDRIVER_PATH,
                options=Chrome_Options
            )

        except Exception as e:
            logging.warning(f"{Date()} General Library - {str(e)}.")

            if "session not created" in str(e) and not self.Internally_Requested:
                e = str(e).strip('\n')
                Message = f"Screenshot request terminated for result number {str(self.Screenshot_ID)} by application, please refer to the log."
                Message_E = e.replace("Message: session not created: ", "")
                Message_E = Message_E.replace("This version of", "The installed version of")
                logging.warning(f"Screenshot Request Error: {Message_E}.")
                logging.warning(f"Kindly replace the Chrome Web Driver, located at {Chrome_Config[1]}, with the latest one from http://chromedriver.chromium.org/downloads that matches the version of Chrome installed on your system.")
                self.Create_Event(Message)
                self.Cursor.execute('UPDATE results SET screenshot_requested = %s WHERE result_id = %s', (False, self.Screenshot_ID,))
                self.Connection.commit()
            
            return None

        Driver.get(self.Screenshot_Link)
        Driver.implicitly_wait(10)
        time.sleep(10)
        Total_Height = Driver.execute_script("return document.body.scrollHeight")
        Driver.set_window_size(1920, Total_Height)
        Driver.save_screenshot(os.path.join(self.File_Path, "static/protected/screenshots", Screenshot_File))
        Driver.close()

        if not self.Internally_Requested:
            self.Cursor.execute('UPDATE results SET screenshot_url = %s WHERE result_id = %s', (Screenshot_File, self.Screenshot_ID,))
            self.Connection.commit()

        else:
            return Screenshot_File

    def Create_Event(self, Description):

        try:
            self.Cursor.execute("INSERT INTO events (description, created_at) VALUES (%s,%s)", (Description, Date()))
            self.Connection.commit()

        except Exception as e:
            logging.error(f"{Date()} General Library - {str(e)}.")

def Request_Handler(URL, Method="GET", User_Agent=True, Application_JSON_CT=False, Accept_XML=False, Accept_Language_EN_US=False, Filter=False, Risky_Plugin=False, Host="", Data={}, **kwargs):

    try:
        Headers = {}

        if type(Data) == dict or type(Data) == str:

            if User_Agent:
                Headers['User-Agent'] = Current_User_Agent

            if Application_JSON_CT:
                Headers['Content-Type'] = 'application/json'

            if Accept_XML:
                Headers['Accept'] = 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'

            if Accept_Language_EN_US:
                Headers['Accept-Language'] = 'en-US,en;q=0.5'

            if kwargs.get("Optional_Headers") and type(kwargs.get("Optional_Headers")) == dict:

                for Header_Key, Header_Value in kwargs["Optional_Headers"].items():
                    Headers[Header_Key] = Header_Value
            
            if Method == "GET":

                if Data:
                    Response = requests.get(URL, headers=Headers, data=Data, verify=False).text

                else:
                    Response = requests.get(URL, headers=Headers, verify=False).text

            elif Method == "POST":

                if Data:
                    Response = requests.post(URL, headers=Headers, data=Data, verify=False).text

                else:
                    Response = requests.post(URL, headers=Headers, verify=False).text

            else:
                logging.warning(f"{Date()} General Library - The supplied method is not supported.")
                return None

            if kwargs.get("Scrape_Regex_URL"):
                Scrape_Regex_URL = kwargs["Scrape_Regex_URL"]
                Scrape_URLs = []
                Content_String = str(Response)

                try:
                    Scrape_URLs_Raw = re.findall(Scrape_Regex_URL, Content_String)

                    for Temp_URL_Extensions in Scrape_URLs_Raw:

                        if not Temp_URL_Extensions in Scrape_URLs:
                            Scrape_URLs.append(Temp_URL_Extensions)

                except:
                    logging.warning(f"{Date()} General Library - Failed to regex URLs.")

                return Scrape_URLs

            else:

                if Filter and str(Host) != "":
                    Filtered_Response = Response_Filter(Response, str(Host), Risky_Plugin=Risky_Plugin)
                    return {"Regular": Response, "Filtered": Filtered_Response}

                else:
                    return Response

        else:
            logging.warning(f"{Date()} General Library - The data field needs to be in a dictionary or string format.")

    except Exception as e:
        logging.warning(f"{Date()} General Library - {str(e)}.")

def Date(Additional_Last_Days=0, Date_Only=False):

    if Additional_Last_Days > 0:
        Additional_Last_Days_Range = Additional_Last_Days - 1
        Real_Dates = []

        while Additional_Last_Days_Range < Additional_Last_Days and Additional_Last_Days_Range >= 0:
            Today = datetime.datetime.now()
            Day = datetime.timedelta(days=Additional_Last_Days_Range)
            Real_Date = Today - Day

            if Date_Only:
                Real_Date = str(Real_Date.strftime('%Y-%m-%d'))

            else:
                Real_Date = str(Real_Date.strftime('%Y-%m-%d %H:%M:%S'))

            Real_Dates.append(Real_Date)
            Additional_Last_Days_Range -= 1

        return Real_Dates

    else:

        if Date_Only:
            return str(datetime.datetime.now().strftime('%Y-%m-%d'))

        else:
            return str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

def Get_Limit(kwargs):

    try:

        if kwargs.get('Limit'):

            if int(kwargs["Limit"]) > 0:
                Limit = int(kwargs["Limit"])

            else:
                Limit = 10

        else:
            Limit = 10

        return Limit

    except:
        logging.warning(f"{Date()} General Library - Failed to set limit.")

def Logging(Directory, Plugin_Name):

    try:
        Main_File = f"{Plugin_Name}-log-file.log"
        General_Directory_Search = re.search(r"(.*)\/\d{4}\/\d{2}\/\d{2}", Directory)

        if General_Directory_Search:
            Complete_File = os.path.join(General_Directory_Search.group(1), Main_File)
            return Complete_File

    except:
        logging.warning(f"{Date()} General Library - Failed to initialise logging.")


def Get_Cache(Directory, Plugin_Name):
    Main_File = f"{Plugin_Name}-cache.txt"
    General_Directory_Search = re.search(r"(.*)\/\d{4}\/\d{2}\/\d{2}", Directory)

    if General_Directory_Search:
        Complete_File = os.path.join(General_Directory_Search.group(1), Main_File)

        try:

            if os.path.exists(Complete_File):
                File_Input = open(Complete_File, "r")
                Cached_Data = File_Input.read()
                File_Input.close()
                return Cached_Data

            else:
                logging.info(f"{Date()} General Library - No cache file found, caching will not be used for this session.")
                return []

        except:
            logging.warning(f"{Date()} General Library - Failed to read file.")

    else:
        logging.warning(f"{Date()} General Library - Failed to regex directory. Cache not read.")

def Write_Cache(Directory, Current_Cached_Data, Data_to_Cache, Plugin_Name):

    if Data_to_Cache:
        Open_File_Type = "w"

        if Current_Cached_Data:
            Open_File_Type = "a"

        Main_File = f"{Plugin_Name}-cache.txt"
        General_Directory_Search = re.search(r"(.*)\/\d{4}\/\d{2}\/\d{2}", Directory)

        if General_Directory_Search:
            Complete_File = os.path.join(General_Directory_Search.group(1), Main_File)

            try:
                File_Output = open(Complete_File, Open_File_Type)
                Current_Output_Data = "\n".join(Data_to_Cache) + "\n"
                File_Output.write(Current_Output_Data)
                File_Output.close()

            except:
                logging.warning(f"{Date()} General Library - Failed to create file.")

        else:
            logging.warning(f"{Date()} General Library - Failed to regex directory. Cache not written.")

def Convert_to_List(String):

    try:

        if ', ' in String:
            List = String.split(', ')
            return List

        elif ',' in String:
            List = String.split(',')
            return List

        else:
            List = [String]
            return List

    except:
        logging.warning(f"{Date()} General Library - Failed to convert the provided query to a list.")

class Connections():

    def __init__(self, Input, Plugin_Name, Domain, Result_Type, Task_ID, Concat_Plugin_Name):

        try:
            self.Plugin_Name = str(Plugin_Name)
            self.Domain = str(Domain)
            self.Result_Type = str(Result_Type)
            self.Task_ID = str(Task_ID)
            self.Input = str(Input)
            self.Concat_Plugin_Name = str(Concat_Plugin_Name)

        except:
            logging.warning(f"{Date()} General Library - Error setting initial variables.")

    def Output(self, Complete_File_List, Link, DB_Title, Directory_Plugin_Name, **kwargs):

        try:
            Text_Complete_Files = "\n- ".join(Complete_File_List)

            if kwargs.get("Dump_Types"):
                self.Dump_Types = kwargs["Dump_Types"]
                Joined_Dump_Types = ", ".join(Dump_Types)
                self.Title = f"Data for input: {self.Input}, found by Scrummage plugin {self.Plugin_Name}.\nData types include: {Joined_Dump_Types}.\nAll data is stored in\n- {Text_Complete_Files}."
                self.Ticket_Subject = f"Scrummage {self.Plugin_Name} results for query {self.Input}."
                NL_Joined_Dump_Types = "\n- ".join(Dump_Types)
                self.Ticket_Text = f"Results were identified for the search {self.Input} performed by the Scrummage plugin {self.Plugin_Name}.\nThe following types of sensitive data were found:\n- {NL_Joined_Dump_Types}. Please ensure these results do not pose a threat to your organisation, and take the appropriate action necessary if they pose a security risk.\n\nResult data can be found in the following output files:\n- {Text_Complete_Files}."

            else:
                self.Title = f"Data for input: {self.Input}, found by Scrummage plugin {self.Plugin_Name}.\nAll data is stored in the files:\n- {Text_Complete_Files}."
                self.Ticket_Subject = f"Scrummage {self.Plugin_Name} results for query {self.Input}."
                self.Ticket_Text = f"Results were identified for the search {self.Input} performed by the Scrummage plugin {self.Plugin_Name}. Please ensure these results do not pose a threat to your organisation, and take the appropriate action necessary if they pose a security risk.\n\nResult data can be found in the following output files:\n- {Text_Complete_Files}."

        except:
            logging.warning(f"{Date()} General Library - Error setting unique variables.")

        logging.info(f"{Date()} General Library - Adding item to Scrummage database and other configured outputs.")
        CSV_File = Connectors.CSV_Output(DB_Title, self.Plugin_Name, self.Domain, Link, self.Result_Type, ", ".join(Complete_File_List), self.Task_ID, Directory_Plugin_Name)
        DOCX_File = Connectors.DOCX_Output(DB_Title, self.Plugin_Name, self.Domain, Link, self.Result_Type, "\n".join(Complete_File_List), self.Task_ID, Directory_Plugin_Name)

        if CSV_File:
            Complete_File_List.append(CSV_File)

        if DOCX_File:
            Complete_File_List.append(DOCX_File)

        Relative_File_List = []

        for File in Complete_File_List:
            Relative_File = File.replace(os.path.dirname(os.path.realpath('__file__')), "")
            Relative_File_List.append(Relative_File)

        Automated_Screenshots = Load_Web_Scrape_Risk_Configuration()

        if Automated_Screenshots[1]:
            File_Dir = os.path.dirname(os.path.realpath('__file__'))
            Screenshot_Object = Screenshot(File_Dir, True, Screenshot_Link=Link)
            Screenshot_Path = Screenshot_Object.Grab_Screenshot()
            Connectors.Main_Database_Insert(DB_Title, self.Plugin_Name, self.Domain, Link, self.Result_Type, ", ".join(Relative_File_List), self.Task_ID, Screenshot_Path=Screenshot_Path)

        else:
            Connectors.Main_Database_Insert(DB_Title, self.Plugin_Name, self.Domain, Link, self.Result_Type, ", ".join(Relative_File_List), self.Task_ID)

        Connectors.Elasticsearch_Main(DB_Title, self.Plugin_Name, self.Domain, Link, self.Result_Type, ", ".join(Complete_File_List), self.Task_ID, self.Concat_Plugin_Name)
        Connectors.Defect_Dojo_Output(DB_Title, self.Ticket_Text)
        Connectors.Scumblr_Main(self.Input, DB_Title, self.Title)
        Connectors.RTIR_Main(self.Ticket_Subject, self.Ticket_Text)
        Connectors.JIRA_Main(self.Ticket_Subject, self.Ticket_Text)
        Connectors.Email_Main(self.Ticket_Subject, self.Ticket_Text)
        Connectors.Slack_Main(self.Ticket_Text)

def Main_File_Create(Directory, Plugin_Name, Output, Query, Main_File_Extension):
    Main_File = f"Main-file-for-{Plugin_Name}-query-{Query}{Main_File_Extension}"
    Complete_File = os.path.join(Directory, Main_File)
    Appendable_Output_Data = []

    try:

        if not os.path.exists(Complete_File):
            File_Output = open(Complete_File, "w")
            File_Output.write(Output)
            File_Output.close()
            logging.info(f"{Date()} General Library - Main file created.")

        else:

            if not Main_File_Extension == ".json":
                File_Input = open(Complete_File, "r")
                Cache_File_Input = File_Input.read()
                File_Input.close()

                if Appendable_Output_Data:
                    logging.info(f"{Date()} General Library - New data has been discovered and will be appended to the existing file.")
                    Appendable_Output_Data_String = "\n".join(Cache_File_Input)
                    File_Output = open(Complete_File, "a")
                    File_Output.write(f"\n{Appendable_Output_Data_String}\n{Output}")
                    File_Output.close()
                    logging.info(f"{Date()} General Library - Main file appended.")

                else:
                    logging.info(f"{Date()} General Library - No existing data found in file, will overwrite.")
                    os.remove(Complete_File)
                    File_Output = open(Complete_File, "w")
                    File_Output.write(Output)
                    File_Output.close()

            else:
                prv_i = 0
                i = 0

                while os.path.exists(Complete_File):
                    Complete_File = Complete_File.strip(f"-{str(prv_i)}.json")
                    Complete_File = f"{Complete_File}-{str(i)}.json"
                    prv_i = i
                    i += 1

                File_Output = open(Complete_File, "w")
                File_Output.write(Output)
                File_Output.close()
                logging.info(f"{Date()} General Library - Main file created.")

        return Complete_File

    except:
        logging.warning(f"{Date()} General Library - Failed to create main file.")

def Data_Type_Discovery(Data_to_Search):
    # Function responsible for determining the type of data found. Examples: Hash_Type, Credentials, Email, or URL.

    try:
        Dump_Types = []
        Hash_Types = ["MD5", "SHA1", "SHA256"]
        Hash_Type_Dict = {}

        for Hash_Type in Hash_Types:
            Hash_Type_Dict[Hash_Type] = Regex_Checker(Data_to_Search, Hash_Type)

        for Hash_Key, Hash_Value in Hash_Type_Dict.items(): # Hash_Type identification

            if Hash_Value:
                Hash_Type_Line = f"{Hash_Key} hash"

                if not Hash_Type_Line in Dump_Types:
                    Dump_Types.append(Hash_Type_Line)

            else:
                pass

        if Regex_Checker(Data_to_Search, "Credentials"): # Credentials identification

            if not "Credentials" in Dump_Types:
                Dump_Types.append("Credentials")

        else:

            if Regex_Checker(Data_to_Search, "Email"): # Email Identification

                if not "Email" in Dump_Types:
                    Dump_Types.append("Email")

            if Regex_Checker(Data_to_Search, "URL"): # URL Indentification

                if not "URL" in Dump_Types:
                    Dump_Types.append("URL")

        return Dump_Types

    except:
        logging.warning(f"{Date()} General Library - Failed to determine data type.")

def Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Output_Data, Query_Result_Name, The_File_Extension):

    try:
        Query_Bad_Characters = Bad_Characters
        Query_Bad_Characters.extend(["https://", "http://", "www.", "=", ",", " ", "@", ":", "---", "--"])

        for Character in Query_Bad_Characters:

            if Character in Query:
                Query = Query.replace(Character, "-")

            if Character in Query_Result_Name and Character not in ["https://", "http://", "www."]:
                Query_Result_Name = Query_Result_Name.replace(Character, "-")

            elif Character in Query_Result_Name and Character in ["https://", "http://", "www."]:
                Query_Result_Name = Query_Result_Name.replace(Character, "")

        try:
            The_File = f"{Plugin_Name}-Query-{Query}-{Query_Result_Name}{The_File_Extension}"
            Complete_File = os.path.join(Directory, The_File)

            if not os.path.exists(Complete_File):

                with open(Complete_File, 'w') as Current_Output_file:
                    Current_Output_file.write(Output_Data)

                logging.info(f"{Date()} General Library - File: {Complete_File} created.")

            else:
                logging.info(f"{Date()} General Library - File already exists, skipping creation.")

            return Complete_File

        except:
            logging.warning(f"{Date()} General Library - Failed to create query file.")

    except:
        logging.warning(f"{Date()} General Library - Failed to initialise query file.")

def Load_Location_Configuration():
    Valid_Locations = ['ac', 'ac', 'ad', 'ae', 'af', 'af', 'ag', 'ag', 'ai', 'ai', 'al', 'am', 'am', 'ao', 'aq', 'ar', 'as', 'at', 'au', 'az', 'ba', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bi', 'bj', 'bn', 'bo', 'bo', 'br', 'bs', 'bt', 'bw', 'by', 'by', 'bz', 'ca', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'cn', 'co', 'co', 'co', 'cr', 'cu', 'cv', 'cy', 'cz', 'de', 'dj', 'dk', 'dm', 'do', 'dz', 'ec', 'ec', 'ee', 'eg', 'es', 'et', 'eu', 'fi', 'fj', 'fm', 'fr', 'ga', 'ge', 'ge', 'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gp', 'gp', 'gr', 'gr', 'gt', 'gy', 'gy', 'gy', 'hk', 'hk', 'hn', 'hr', 'ht', 'ht', 'hu', 'hu', 'id', 'id', 'ie', 'il', 'im', 'im', 'in', 'in', 'io', 'iq', 'iq', 'is', 'it', 'je', 'je', 'jm', 'jo', 'jo', 'jp', 'jp', 'ke', 'kg', 'kh', 'ki', 'kr', 'kw', 'kz', 'kz', 'la', 'lb', 'lc', 'li', 'lk', 'ls', 'lt', 'lu', 'lv', 'ly', 'ma', 'ma', 'md', 'me', 'mg', 'mk', 'ml', 'mm', 'mn', 'ms', 'mt', 'mu', 'mv', 'mw', 'mx', 'mx', 'my', 'mz', 'na', 'ne', 'nf', 'ng', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nr', 'nu', 'nz', 'om', 'pa', 'pe', 'pe', 'pf', 'pg', 'ph', 'pk', 'pk', 'pl', 'pl', 'pn', 'pr', 'ps', 'ps', 'pt', 'py', 'qa', 'qa', 're', 'ro', 'rs', 'rs', 'ru', 'ru', 'rw', 'sa', 'sb', 'sc', 'se', 'sg', 'sh', 'si', 'sk', 'sl', 'sl', 'sm', 'sn', 'so', 'sr', 'st', 'sv', 'sy', 'td', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tt', 'tz', 'ua', 'ua', 'ug', 'uk', 'us', 'us', 'uy', 'uz', 'uz', 'vc', 've', 've', 'vg', 'vi', 'vn', 'vu', 'ws', 'za', 'zm', 'zw']

    try:

        with open(Connectors.Set_Configuration_File()) as JSON_File:  
            Configuration_Data = json.load(JSON_File)
            General_Details = Configuration_Data['general']
            Location = General_Details['location']

            if (len(Location) > 2) or (Location not in Valid_Locations):
                logging.warning(f"{Date()} General Library - An invalid location has been specified, please provide a valid location in the config.json file.")

            else:
                logging.info(f"{Date()} General Library - Country code {Location} selected.")
                return Location

    except:
        logging.warning(f"{Date()} General Library - Failed to load location details.")

def Load_Web_Scrape_Risk_Configuration():
    
    try:

        with open(Connectors.Set_Configuration_File()) as JSON_File:  
            Configuration_Data = json.load(JSON_File)
            Web_Scrape_Details = Configuration_Data['web-scraping']
            Risk_Level = int(Web_Scrape_Details['risk-level'])
            Automated_Screenshots = Web_Scrape_Details['automated-screenshots']

            if Risk_Level > 3 or Risk_Level < 0:
                logging.warning(f"{Date()} General Library - An invalid number has been specified, please provide a valid risk level in the config.json file, with a value from 1 to 3.")

            else:
                return [Risk_Level, Automated_Screenshots]

    except:
        logging.warning(f"{Date()} General Library - Failed to load location details.")

def Make_Directory(Plugin_Name):
    Today = datetime.datetime.now()
    Year = str(Today.year)
    Month = str(Today.month)
    Day = str(Today.day)

    if len(Month) == 1:
        Month = f"0{Month}"

    if len(Day) == 1:
        Day = f"0{Day}"

    File_Path = os.path.dirname(os.path.realpath('__file__'))
    Directory = f"{File_Path}/static/protected/output/{Plugin_Name}/{Year}/{Month}/{Day}"

    if not os.path.isdir(Directory):
        os.makedirs(Directory)
        logging.info(f"{Date()} General Library - Using new directory: {Directory}.")

    else:
        logging.info(f"{Date()} General Library - Using existing directory: {Directory}.")
    
    return Directory

def Get_Title_Requests_Module(URL):

    try:

        if URL.startswith('http://') or URL.startswith('https://'):

            if 'file:/' not in URL:
                Soup = BeautifulSoup(Request_Handler(URL), features="lxml")
                return Soup.title.text

            else:
                logging.warning(f"{Date()} General Library - This function does not work on files.")

        else:
            logging.warning(f"{Date()} General Library - Invalid URL provided.")

    except:
        logging.warning(f"{Date()} General Library - Failed to get title.")

def Get_Title(URL):

    try:

        if URL.startswith('http://') or URL.startswith('https://'):

            if 'file:/' not in URL:
                Soup = BeautifulSoup(urllib.request.urlopen(URL), features="lxml")
                return Soup.title.text

            else:
                logging.warning(f"{Date()} General Library - This function does not work on files.")

        else:
            logging.warning(f"{Date()} General Library - Invalid URL provided.")

    except:
        logging.warning(f"{Date()} General Library - Failed to get title.")

def Response_Filter(Response, Host, Risky_Plugin=False):
    Risk_Level = Load_Web_Scrape_Risk_Configuration()
    Risk_Level = Risk_Level[0]

    if (Risk_Level == 3) or (Risk_Level == 2 and not Risky_Plugin):
        Attributes = ["src", "href"]
        Quotes = ["\"", "\'"]
        Replace_Items = ["/", "./"]
        Replace_Strings = ["js", "assets", "polyfills", "main", "styles", "css", "jquery", "img", "images", "atom", "?", "static", "logo"]

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

def Is_JSON(JSON_String):

    try:
        json_object = json.loads(JSON_String)

    except ValueError as e:
        return False

    return json_object


def Regex_Checker(Query, Type):

    if Type == "Email":
        Regex = re.search(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", Query)

    elif Type == "Domain":
        Regex = re.search(r"[-a-zA-Z0-9@:%_\+~#=]{2,256}\.[a-z]{2,3}(\.[a-z]{2,3})?(\.[a-z]{2,3})?", Query)

    elif Type == "IP":
        Regex = re.search(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", Query)

    elif Type == "URL":
        Regex = re.search(r"(https?\:\/\/(www\.)?)?([-a-zA-Z0-9@:%_\+\-~#=]{2,256})(\.[a-z]{2,3})(\.[a-z]{2,3})?(\.[a-z]{2,3})?", Query)

    elif Type == "MD5":
        Regex = re.search(r"([a-fA-F0-9]{32})\W", Query)

    elif Type == "SHA1":
        Regex = re.search(r"([a-fA-F0-9]{40})\W", Query)

    elif Type == "SHA256":
        Regex = re.search(r"([a-fA-F0-9]{64})\W", Query)

    elif Type == "Credentials":
        Regex = re.search(r"[\w\d\.\-\_]+\@[\w\.]+\:.*", Query)

    else:
        return None

    if Regex:
        return Regex

    else:
        return None