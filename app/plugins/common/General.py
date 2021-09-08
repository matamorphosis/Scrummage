#!/usr/bin/env python3

import time, os, PIL, logging, urllib.request, plugins.common.Common as Common
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

Bad_Characters = ["|", "/", "&", "?", "\\", "\"", "\'", "[", "]", ">", "<", "~", "`", ";", "{", "}", "%", "^"]
Current_User_Agent = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'

class Screenshot:

    def __init__(self, File_Path, Internally_Requested=False, Append_Mode=False, **kwargs):
        self.Internally_Requested = Internally_Requested
        self.Chrome_Config = Common.Configuration(Core=True).Load_Configuration(Object="google_chrome", Details_to_Load=["application_path", "chromedriver_path"])
        self.File_Path = File_Path
        self.Connection = Common.Configuration(Output=True).Load_Configuration(Postgres_Database=True, Object="postgresql")
        self.Cursor = self.Connection.cursor()

        if not self.Internally_Requested and kwargs.get('Screenshot_ID') and kwargs.get('Screenshot_User'):
            self.Screenshot_ID = kwargs['Screenshot_ID']
            self.Screenshot_User = kwargs['Screenshot_User']
            self.Append_Mode = Append_Mode

        elif self.Internally_Requested and kwargs.get('Screenshot_Link'):
            self.Screenshot_ID = False
            self.Screenshot_User = False
            self.Screenshot_Link = kwargs['Screenshot_Link']
            self.Append_Mode = Append_Mode

    def Screenshot_Checker(self):
        logging.info(f"{Common.Date()} Performing verification for screenshot capability.")

        if all(os.path.exists(Config) for Config in self.Chrome_Config): 
            CHROME_PATH = self.Chrome_Config[0]
            CHROMEDRIVER_PATH = self.Chrome_Config[1]
            Chrome_Options = Options()
            Chrome_Options.add_argument("--headless")
            Chrome_Options.add_argument('--no-sandbox')
            Chrome_Options.add_argument('--disable-dev-shm-usage')
            Chrome_Options.binary_location = CHROME_PATH

            try:
                driver = webdriver.Chrome(
                    executable_path=CHROMEDRIVER_PATH,
                    options=Chrome_Options
                )
                return True

            except Exception as e:
                logging.warning(f"{Common.Date()} - General Library - {str(e)}.")

                if "session not created" in str(e):
                    logging.warning(f"\033[0;31mPlease run the \"Fix_ChromeDriver.sh\" script in the installation directory to upgrade the Google Chrome Driver to be in-line with the current version of Google Chrome on this operating system, or replace it manually with the latest version from http://chromedriver.chromium.org/downloads that matches the version of Chrome installed on your system. Screenshot functionality has been disabled in the meantime until this issue is resolved.\033[0m\n")
                    return False

        else:
            logging.warning("\033[0;31mOne or more of the values provided to the google chrome configuration in the config.json file do not reflect real files. Screenshot functionality has been disabled in the meantime. To correct this please accurately fill out the following section in the config.json file (Example values included, please ensure these reflect real files on your system)\n\n    \"google_chrome\": {\n        \"application_path\": \"/usr/bin/google-chrome\",\n        \"chromedriver_path\": \"/usr/bin/chromedriver\"\n    },\n\033[0m")
            return False

    def Grab_Screenshot(self):

        try:
            Bad_Link_Strings = ['.onion', 'general-insurance.coles.com.au', 'magnet:?xt=urn:btih:', 'nameapi.org']

            if not self.Internally_Requested:
                self.Cursor.execute('SELECT link FROM results WHERE result_id = %s', (self.Screenshot_ID,))
                Result = self.Cursor.fetchone()
                self.Screenshot_Link = Result[0]
                Message = f"Screenshot requested for result number {str(self.Screenshot_ID)} by {self.Screenshot_User}."
                logging.warning(Message)
                self.Create_Event(Message)
                self.Cursor.execute('UPDATE results SET screenshot_requested = %s, updated_at = %s WHERE result_id = %s', (True, str(Common.Date()), self.Screenshot_ID,))
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
            
            if self.Append_Mode:
                i = 0
                Current_File = f"{Screenshot_File}.png"
            
                while os.path.isfile(os.path.join(self.File_Path, "static/protected/screenshots", Current_File)):
                    Current_File = f"{Screenshot_File}_{str(i)}.png"
                    i += 1

                Screenshot_File = Current_File
            
            else:
                Screenshot_File = f"{Screenshot_File}.png"
                
            Chrome_Options = Options()
            Chrome_Options.add_argument("--headless")
            Chrome_Options.add_argument('--no-sandbox')
            Chrome_Options.add_argument('--disable-dev-shm-usage')
            Chrome_Options.binary_location = CHROME_PATH

        except Exception as e:
            logging.warning(f"{Common.Date()} - General Library - {str(e)}.")

        try:
            Driver = webdriver.Chrome(
                executable_path=CHROMEDRIVER_PATH,
                options=Chrome_Options
            )

        except Exception as e:
            logging.warning(f"{Common.Date()} - General Library - {str(e)}.")

            if "session not created" in str(e) and not self.Internally_Requested:
                e = str(e).strip('\n')
                Message = f"Screenshot request terminated for result number {str(self.Screenshot_ID)} by application, please refer to the log."
                Message_E = e.replace("Message: session not created: ", "")
                Message_E = Message_E.replace("This version of", "The installed version of")
                logging.warning(f"Screenshot Request Error: {Message_E}.")
                logging.warning(f"Kindly replace the Chrome Web Driver, with the latest one from http://chromedriver.chromium.org/downloads that matches the version of Chrome installed on your system.")
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
        
            if self.Append_Mode:
                self.Cursor.execute('SELECT screenshot_url FROM results WHERE result_id = %s', (self.Screenshot_ID,))
                Existing_URLs = self.Cursor.fetchone()
                Screenshot_File = Existing_URLs[0] + ", " + Screenshot_File
            
            self.Cursor.execute('UPDATE results SET screenshot_url = %s, screenshot_requested = %s, updated_at = %s WHERE result_id = %s', (Screenshot_File, False, str(Common.Date()), self.Screenshot_ID,))
            self.Connection.commit()

        else:
            return Screenshot_File

    def Create_Event(self, Description):

        try:
            self.Cursor.execute("INSERT INTO events (description, created_at) VALUES (%s,%s)", (Description, Common.Date()))
            self.Connection.commit()

        except Exception as e:
            logging.error(f"{Common.Date()} - General Library - {str(e)}.")


def Get_Limit(Limit):

    try:

        if int(Limit) > 0:
            Limit = int(Limit)

        else:
            Limit = 10

        return Limit

    except Exception as e:
        logging.warning(f"{Common.Date()} - General Library - Failed to set provided limit, returning default - {str(e)}.")
        return 10

def Logging(Directory, Plugin_Name):

    try:
        Main_File = f"{Plugin_Name}-log-file.log"
        General_Directory_Search = Common.Regex_Handler(Directory, Custom_Regex=r"(.*)\/\d{4}\/\d{2}\/\d{2}")

        if General_Directory_Search:
            Complete_File = os.path.join(General_Directory_Search.group(1), Main_File)
            return Complete_File

    except Exception as e:
        logging.warning(f"{Common.Date()} - General Library - Failed to initialise logging. {str(e)}.")

def Get_Plugin_Logging_Name(Plugin_Name):

    try:

        for Item in ["_", "-"]:
            Plugin_Name = Plugin_Name.replace(Item, "")

        return Plugin_Name.lower().title() + " Search"

    except Exception as e:
        logging.warning(f"DATE FUNCTION ERROR - General Library - {str(e)}.")

class Cache:

    def __init__(self, Directory, Plugin_Name):
        Cache_File = f"{Plugin_Name}-cache.txt"
        General_Directory_Search = Common.Regex_Handler(Directory, Custom_Regex=r"(.*)\/\d{4}\/\d{2}\/\d{2}")

        if General_Directory_Search:
            self.Complete_File = os.path.join(General_Directory_Search.group(1), Cache_File)

    def Get_Cache(self):

        try:

            if os.path.exists(self.Complete_File):
                File_Input = open(self.Complete_File, "r")
                self.Cached_Data = File_Input.read()
                File_Input.close()

            else:
                logging.info(f"{Common.Date()} - General Library - No cache file found, caching will not be used for this session.")
                self.Cached_Data = []

            return self.Cached_Data

        except Exception as e:
            logging.warning(f"{Common.Date()} - General Library - Failed to read file. {str(e)}.")

    def Write_Cache(self, Data_to_Cache):

        if Data_to_Cache:
            Open_File_Type = "w"

            if self.Cached_Data:
                Open_File_Type = "a"

            try:
                File_Output = open(self.Complete_File, Open_File_Type)
                Current_Output_Data = "\n".join(Data_to_Cache) + "\n"
                File_Output.write(Current_Output_Data)
                File_Output.close()

            except Exception as e:
                logging.warning(f"{Common.Date()} - General Library - Failed to create file. {str(e)}.")

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

    except Exception as e:
        logging.warning(f"{Common.Date()} - General Library - Failed to convert the provided query to a list. {str(e)}.")

class Connections:

    def __init__(self, Input, Plugin_Name, Domain, Result_Type, Task_ID, Concat_Plugin_Name):

        try:
            self.Plugin_Name = str(Plugin_Name)
            self.Domain = str(Domain)
            self.Result_Type = str(Result_Type)
            self.Task_ID = str(Task_ID)
            self.Input = str(Input)
            self.Concat_Plugin_Name = str(Concat_Plugin_Name)

        except Exception as e:
            logging.warning(f"{Common.Date()} - General Library - Error setting initial variables. {str(e)}.")

    def Output(self, Complete_File_List, Link, DB_Title, Directory_Plugin_Name, Dump_Types=[]):

        try:

            try:
                Text_Complete_Files = "\n- ".join(Complete_File_List)

                if type(Dump_Types) == list and len(Dump_Types) > 0:
                    self.Dump_Types = Dump_Types
                    Joined_Dump_Types = ", ".join(self.Dump_Types)
                    self.Title = f"Data for input: {self.Input}, found by Scrummage plugin {self.Plugin_Name}.\nData types include: {Joined_Dump_Types}.\nAll data is stored in\n- {Text_Complete_Files}."
                    self.Ticket_Subject = f"Scrummage {self.Plugin_Name} results for query {self.Input}."
                    NL_Joined_Dump_Types = "\n- ".join(self.Dump_Types)
                    self.Ticket_Text = f"Results were identified for the search {self.Input} performed by the Scrummage plugin {self.Plugin_Name}.\nThe following types of sensitive data were found:\n- {NL_Joined_Dump_Types}. Please ensure these results do not pose a threat to your organisation, and take the appropriate action necessary if they pose a security risk.\n\nResult data can be found in the following output files:\n- {Text_Complete_Files}."

                else:
                    self.Title = f"Data for input: {self.Input}, found by Scrummage plugin {self.Plugin_Name}.\nAll data is stored in the files:\n- {Text_Complete_Files}."
                    self.Ticket_Subject = f"Scrummage {self.Plugin_Name} results for query {self.Input}."
                    self.Ticket_Text = f"Results were identified for the search {self.Input} performed by the Scrummage plugin {self.Plugin_Name}. Please ensure these results do not pose a threat to your organisation, and take the appropriate action necessary if they pose a security risk.\n\nResult data can be found in the following output files:\n- {Text_Complete_Files}."

            except Exception as e:
                logging.warning(f"{Common.Date()} - General Library - Error setting unique variables. {str(e)}.")

            logging.info(f"{Common.Date()} - General Library - Adding item to Scrummage database and other configured outputs.")
            Connector_Object = Common.Configuration(Output=True)
            CSV_File = Common.CSV_Output(Connector_Object, DB_Title, self.Plugin_Name, self.Domain, Link, self.Result_Type, ", ".join(Complete_File_List), self.Task_ID, Directory_Plugin_Name)
            DOCX_File = Common.DOCX_Output(Connector_Object, DB_Title, self.Plugin_Name, self.Domain, Link, self.Result_Type, "\n".join(Complete_File_List), self.Task_ID, Directory_Plugin_Name)

            if CSV_File:
                Complete_File_List.append(CSV_File)

            if DOCX_File:
                Complete_File_List.append(DOCX_File)

            Relative_File_List = []

            for File in Complete_File_List:
                Relative_File = File.replace(os.path.dirname(os.path.realpath('__file__')), "")
                Relative_File_List.append(Relative_File)

            Automated_Screenshots = Common.Configuration(Core=True).Load_Configuration(Object="web_scraping", Details_to_Load=["risk_level", "automated_screenshots"])

            if Automated_Screenshots[1]:
                File_Dir = os.path.dirname(os.path.realpath('__file__'))
                Screenshot_Path = Screenshot(File_Dir, Internally_Requested=True, Screenshot_Link=Link).Grab_Screenshot()
                Common.Main_Database_Insert(Connector_Object, DB_Title, self.Plugin_Name, self.Domain, Link, self.Result_Type, ", ".join(Relative_File_List), self.Task_ID, Screenshot_Path=Screenshot_Path)

            else:
                Common.Main_Database_Insert(Connector_Object, DB_Title, self.Plugin_Name, self.Domain, Link, self.Result_Type, ", ".join(Relative_File_List), self.Task_ID)

            Common.Elasticsearch_Main(Connector_Object, DB_Title, self.Plugin_Name, self.Domain, Link, self.Result_Type, ", ".join(Complete_File_List), self.Task_ID, self.Concat_Plugin_Name)
            Common.Defect_Dojo_Output(Connector_Object, DB_Title, self.Ticket_Text)
            Common.Scumblr_Main(Connector_Object, self.Input, DB_Title, self.Title)
            Common.RTIR_Main(Connector_Object, self.Ticket_Subject, self.Ticket_Text)
            Common.JIRA_Main(Connector_Object, self.Ticket_Subject, self.Ticket_Text)
            Common.Email_Main(Connector_Object, self.Ticket_Subject, self.Ticket_Text)
            Common.Slack_Main(Connector_Object, self.Ticket_Text)

        except Exception as e:
            logging.warning(f"{Common.Date()} - General Library - Error handling outputs. {str(e)}.")

def Main_File_Create(Directory, Plugin_Name, Output, Query, Main_File_Extension):
    Main_File = f"Main-file-for-{Plugin_Name}-query-{Query}{Main_File_Extension}"
    Complete_File = os.path.join(Directory, Main_File)
    Appendable_Output_Data = []

    try:

        if not os.path.exists(Complete_File):
            File_Output = open(Complete_File, "w")
            File_Output.write(Output)
            File_Output.close()
            logging.info(f"{Common.Date()} - General Library - Main file created.")

        else:

            if not Main_File_Extension == ".json":
                File_Input = open(Complete_File, "r")
                Cache_File_Input = File_Input.read()
                File_Input.close()

                if Appendable_Output_Data:
                    logging.info(f"{Common.Date()} - General Library - New data has been discovered and will be appended to the existing file.")
                    Appendable_Output_Data_String = "\n".join(Cache_File_Input)
                    File_Output = open(Complete_File, "a")
                    File_Output.write(f"\n{Appendable_Output_Data_String}\n{Output}")
                    File_Output.close()
                    logging.info(f"{Common.Date()} - General Library - Main file appended.")

                else:
                    logging.info(f"{Common.Date()} - General Library - No existing data found in file, will overwrite.")
                    os.remove(Complete_File)
                    File_Output = open(Complete_File, "w")
                    File_Output.write(Output)
                    File_Output.close()

            else:
                prv_i = 0
                i = 0

                while os.path.exists(Complete_File):
                    Complete_File = Complete_File.strip(f"-{str(prv_i)}{Main_File_Extension}")
                    Complete_File = f"{Complete_File}-{str(i)}{Main_File_Extension}"
                    prv_i = i
                    i += 1

                File_Output = open(Complete_File, "w")
                File_Output.write(Output)
                File_Output.close()
                logging.info(f"{Common.Date()} - General Library - Main file created.")

        return Complete_File

    except Exception as e:
        logging.warning(f"{Common.Date()} - General Library - Failed to create main file. {str(e)}.")

def Data_Type_Discovery(Data_to_Search):
    # Function responsible for determining the type of data found. Examples: Hash_Type, Credentials, Email, or URL.

    try:
        Dump_Types = []
        Hash_Types = ["MD5", "SHA1", "SHA256"]
        Hash_Type_Dict = {}

        for Hash_Type in Hash_Types:
            Hash_Type_Dict[Hash_Type] = Common.Regex_Handler(Data_to_Search, Type=Hash_Type)

        for Hash_Key, Hash_Value in Hash_Type_Dict.items(): # Hash_Type identification

            if Hash_Value:
                Hash_Type_Line = f"{Hash_Key} hash"

                if not Hash_Type_Line in Dump_Types:
                    Dump_Types.append(Hash_Type_Line)

            else:
                pass

        if Common.Regex_Handler(Data_to_Search, Type="Credentials"): # Credentials identification

            if not "Credentials" in Dump_Types:
                Dump_Types.append("Credentials")

        else:

            if Common.Regex_Handler(Data_to_Search, Type="Email"): # Email Identification

                if not "Email" in Dump_Types:
                    Dump_Types.append("Email")

            if Common.Regex_Handler(Data_to_Search, Type="URL"): # URL Indentification

                if not "URL" in Dump_Types:
                    Dump_Types.append("URL")

        return Dump_Types

    except Exception as e:
        logging.warning(f"{Common.Date()} - General Library - Failed to determine data type. {str(e)}.")

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

                if The_File_Extension == ".jpg":
                    Image_File = PIL.Image.open(Output_Data)
                    Image_File.save(Complete_File)

                else:
                    
                    with open(Complete_File, 'w') as Current_Output_file:
                        Current_Output_file.write(Output_Data)

                logging.info(f"{Common.Date()} - General Library - File: {Complete_File} created.")

            else:
                logging.info(f"{Common.Date()} - General Library - File already exists, skipping creation.")

            return Complete_File

        except Exception as e:
            logging.warning(f"{Common.Date()} - General Library - Failed to create query file. {str(e)}.")

    except Exception as e:
        logging.warning(f"{Common.Date()} - General Library - Failed to initialise query file. {str(e)}.")

def Make_Directory(Plugin_Name):
    Today = Common.Date(Full_Timestamp=True)
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
        logging.info(f"{Common.Date()} - General Library - Using new directory: {Directory}.")

    else:
        logging.info(f"{Common.Date()} - General Library - Using existing directory: {Directory}.")
    
    return Directory

def Get_Title(URL, Requests=False):

    try:

        if URL.startswith('http'):

            if Requests:
                Soup = BeautifulSoup(Common.Request_Handler(URL), features="lxml")

            else:
                # Bandit detects the following line as a potential vulnerability. The reason being it is susceptible to URLs beginning with file:/, hence the condition check above to ensure URL begins with http.
                # Unfortunately some plugins require this to work properly.
                Soup = BeautifulSoup(urllib.request.urlopen(URL), features="lxml")

            return Soup.title.text

        else:
            logging.warning(f"{Common.Date()} - General Library - Invalid URL provided.")

    except Exception as e:
        logging.warning(f"{Common.Date()} - General Library - Failed to get title. {str(e)}.")

def JSONDict_to_HTML(JSON_Data, JSON_Data_Output, Title):

    try:

        if type(JSON_Data) == list:
            HTML_Data = ["<head>", "<style>", "  * {", "    margin: auto;", "    background-color: #000;", "    color: #fff;", "    font-size: 14px;", "    font-family: arial;", "    text-align: center;", "  }", "  table {", "    text-align: center;", "    border-collapse: collapse;", "    border-radius: 2px;", "    width: 99%;", "    overflow: hidden;", "    table-layout: fixed;", "  }", "  table tr {", "    text-align: center;", "  }", "  table tr th {", "    background-color: #303030;", "    padding: 5px;", "   text-align: left;", "  }", "  table tr td {", "    padding: 5px;", "    background-color: #1A1A1A;", "   text-align: left;", "  }", "  .title {", "    color: #DC143C;", "    font-family: arial;", "    font-size: 16pt;", "    font-weight: normal;", "    padding: 5px 10px 5px 10px;", "    float: left;", "  }","  textarea {", "    resize: none;", "    border: 0px;", "    border-radius: 2px;", "    background-color: #1A1A1A;", "    text-align: left;", "  }", "</style>", "</head>", "<body>", f"<h1 class=\"title\">Scrummage Result for {Title}</h1>"]
            HTML_Table = ["  <table>", "    <tr>", "      <th>Item</th>", "      <th>Value</th>", "    </tr>"]

            for JSON_Block in JSON_Data:

                for Key, Value in JSON_Block.items():
                    HTML_Table.append("    <tr>")
                    Key = f"      <td>{str(Key)}</td>"
                    Value = f"      <td>{str(Value)}</td>"
                    HTML_Table.extend([Key, Value])
                    HTML_Table.append("    </tr>")

            HTML_Table.append("  </table>")
            HTML_Data.extend(HTML_Table)
            HTML_Data.extend(["<br />", "<h1 class=\"title\">Original JSON Response</h1>", f"<textarea style=\"width: 99%; height:400px;\">{JSON_Data_Output}</textarea>", "</body>"])
            return "\n".join(HTML_Data)

        else:
            logging.warning(f"{Common.Date()} - General Library - Data provided in the wrong format, needs to be a list.")
            return None

    except Exception as e:
        logging.warning(f"{Common.Date()} - General Library - Failed to convert provided JSON data to HTML. {str(e)}.")

def CSV_to_HTML(CSV_Data, Title):

    try:

        if type(CSV_Data) == list:
            HTML_Data = ["<head>", "<style>", "  * {", "    margin: auto;", "    background-color: #000;", "    color: #fff;", "    font-size: 14px;", "    font-family: arial;", "    text-align: center;", "  }", "  table {", "    text-align: center;", "    border-collapse: collapse;", "    border-radius: 2px;", "    width: 99%;", "    overflow: hidden;", "    table-layout: fixed;", "  }", "  table tr {", "    text-align: center;", "  }", "  table tr th {", "    background-color: #303030;", "    padding: 5px;", "   text-align: left;", "  }", "  table tr td {", "    padding: 5px;", "    background-color: #1A1A1A;", "   text-align: left;", "  }", "  .title {", "    color: #DC143C;", "    font-family: arial;", "    font-size: 16pt;", "    font-weight: normal;", "    padding: 5px 10px 5px 10px;", "    float: left;", "  }","  textarea {", "    resize: none;", "    border: 0px;", "    border-radius: 2px;", "    background-color: #1A1A1A;", "    text-align: left;", "  }", "</style>", "</head>", "<body>", f"<h1 class=\"title\">Scrummage Result for {Title}</h1>"]
            HTML_Table = ["  <table>"]

            for CSV_Line in CSV_Data:
                HTML_Table.append("    <tr>")
                Values = []
                Tag = ""

                if CSV_Line == CSV_Data[0]:
                    Tag = "th"

                else:
                    Tag = "td"

                for CSV_Item in CSV_Line.split(","):
                    Value = f"      <{Tag}>{str(CSV_Item)}</{Tag}>"
                    Values.append(Value)

                if len(Values) > 0:
                    HTML_Table.extend(Values)

                HTML_Table.append("    </tr>")

            HTML_Table.extend(["  </table>", "</body>"])
            HTML_Data.extend(HTML_Table)
            return "\n".join(HTML_Data)

        else:
            logging.warning(f"{Common.Date()} - General Library - Data provided in the wrong format, needs to be a list.")
            return None

    except Exception as e:
        logging.warning(f"{Common.Date()} - General Library - Failed to convert provided CSV data to HTML. {str(e)}.")

def CSV_to_JSON(Query, CSV_Data):

    try:

        if type(CSV_Data) == list:
            JSON_Data = {Query: []}

            for CSV_Line in CSV_Data:

                if CSV_Line != CSV_Data[0]:
                    Split_CSV_Line = CSV_Line.split(",")
                    JSON_Data[Query].append({"Domain": Split_CSV_Line[0], "IP Address": Split_CSV_Line[1]})

            Indented_Registration_Response = Common.JSON_Handler(JSON_Data).Dump_JSON()
            return Indented_Registration_Response

        else:
            logging.warning(f"{Common.Date()} - General Library - Data provided in the wrong format, needs to be a list.")
            return None

    except Exception as e:
        logging.warning(f"{Common.Date()} - General Library - Failed to convert provided CSV data to JSON. {str(e)}.")

def Encoder(To_Encode, URLSafe=False, Type="Base64"):
    # Currently just handles b64 encoding as no other encoding types are required; however, this function can be scaled with future demand.

    try:

        if Type == "Base64":
            import base64

            if URLSafe:
                return base64.urlsafe_b64encode(To_Encode.encode()).decode()

            else:
                return base64.b64encode(To_Encode.encode()).decode()

    except Exception as e:
        logging.warning(f"{Common.Date()} - General Library - Failed to encode data. {str(e)}.")