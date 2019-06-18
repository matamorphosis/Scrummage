#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime, os, sys, re, requests, urllib, json, plugins.common.Connectors as Connectors
from bs4 import BeautifulSoup

Bad_Characters = ["|", "/", "&", "?", "\\", "\"", "\'", "[", "]", ">", "<", "~", "`", ";", "{", "}", "%", "^"]
Configuration_File = os.path.join('plugins/common/configuration', 'config.json')

def Logging(Directory, Plugin_Name):
    Main_File = Plugin_Name + "-log-file.txt"
    General_Directory_Search = re.search(r"(.*)\/\d{4}\/\d{2}\/\d{2}", Directory)

    if General_Directory_Search:
        Complete_File = os.path.join(General_Directory_Search.group(1), Main_File)
        print(str(datetime.datetime.now()) + " Printing results to the file: " + str(Complete_File))

        if not os.path.exists(Complete_File):
            Output = open(Complete_File, "w")
            sys.stdout = Output

        else:
            Output = open(Complete_File, "a")
            sys.stdout = Output

def Get_Cache(Directory, Plugin_Name):
    Main_File = Plugin_Name + "-cache.txt"
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
                print(str(datetime.datetime.now()) + "[i] No cache file found, caching will not be used for this session.")

        except:
            print(str(datetime.datetime.now()) + " Failed to read file.")

    else:
        print(str(datetime.datetime.now()) + " Failed to regex directory. Cache not read.")

def Write_Cache(Directory, Data_to_Cache, Plugin_Name, Open_File_Type):
    Main_File = Plugin_Name + "-cache.txt"
    General_Directory_Search = re.search(r"(.*)\/\d{4}\/\d{2}\/\d{2}", Directory)

    if General_Directory_Search:
        Complete_File = os.path.join(General_Directory_Search.group(1), Main_File)

        try:
            File_Output = open(Complete_File, Open_File_Type)
            Current_Output_Data = "\n".join(Data_to_Cache) + "\n"
            File_Output.write(Current_Output_Data)
            File_Output.close()

        except:
            print(str(datetime.datetime.now()) + " Failed to create file.")

    else:
        print(str(datetime.datetime.now()) + " Failed to regex directory. Cache not written.")

def Convert_to_List(String):

    if ', ' in String:
        List = String.split(', ')
        return List

    elif ',' in String:
        List = String.split(',')
        return List

    else:
        List = [String]
        return List

def Connections(Complete_File, Input, Plugin_Name, Link, Domain, Result_Type, Task_ID, DB_Title, **kwargs):

    if "Dump_Types" in kwargs:
        Dump_Types = kwargs["Dump_Types"]
        Title = "Data for input: " + Input + ", found by Scrummage plugin " + Plugin_Name + ".\nData types include: " + ", ".join(Dump_Types) + ".\nAll data is stored in " + Complete_File + "."
        Ticket_Subject = "Scrummage " + Plugin_Name + " results for query " + Input + "."
        Ticket_Text = "Results were identified for the search " + Input + " performed by the Scrummage plugin " + Plugin_Name + ".\nThe following types of sensitive data were found:\n - " + "\n - ".join(Dump_Types) + ". Please ensure these results do not pose a threat to your organisation, and take the appropriate action necessary if they pose a security risk. The result data is stored in a file located at " + Complete_File + "."

    else:
        Title = "Data for input: " + Input + ", found by Scrummage plugin " + Plugin_Name + ".\nAll data is stored in " + Complete_File + "."
        Ticket_Subject = "Scrummage " + Plugin_Name + " results for query " + Input + "."
        Ticket_Text = "Results were identified for the search " + Input + " performed by the Scrummage plugin " + Plugin_Name + ". Please ensure these results do not pose a threat to your organisation, and take the appropriate action necessary if they pose a security risk. The result data is stored in a file located at " + Complete_File + "."

    Connectors.Scumblr_Main(Input, DB_Title, Title)
    Connectors.RTIR_Main(Ticket_Subject, Ticket_Text)
    Connectors.JIRA_Main(Ticket_Subject, Ticket_Text)
    Connectors.Email_Main(Ticket_Subject, Ticket_Text)
    Connectors.Slack_Main(Ticket_Text)
    Relative_File = Complete_File.replace(os.path.dirname(os.path.realpath('__file__')), "")
    print(str(datetime.datetime.now()) + " Adding item to Scrummage database.")

    if DB_Title:
        Connectors.Main_Database_Insert(DB_Title, Plugin_Name, Domain, Link, Result_Type, Relative_File, Task_ID)

    else:
        Connectors.Main_Database_Insert(Plugin_Name, Plugin_Name, Domain, Link, Result_Type, Relative_File, Task_ID)

def Main_File_Create(Directory, Plugin_Name, Output, Query, Main_File_Extension):
    Main_File = "Main-file-for-" + Plugin_Name + "-query-" + Query + Main_File_Extension
    Complete_File = os.path.join(Directory, Main_File)
    Appendable_Output_Data = []

    try:

        if not os.path.exists(Complete_File):
            File_Output = open(Complete_File, "w")
            File_Output.write(Output)
            File_Output.close()
            print(str(datetime.datetime.now()) + " Main file created.")

        else:

            if not Main_File_Extension == ".json":
                File_Input = open(Complete_File, "r")
                Cache_File_Input = File_Input.read()
                File_Input.close()
                
                for Temp_Scrape in Cache_File_Input:

                    if not Temp_Scrape in Cache_File_Input:
                        Appendable_Output_Data.append(Temp_Scrape)

                if Appendable_Output_Data:
                    print(str(datetime.datetime.now()) + " New data has been discovered and will be appended to the existing file.")
                    Appendable_Output_Data_String = "\n".join(Appendable_Output_Data)
                    File_Output = open(Complete_File, "a")
                    File_Output.write("\n" + Appendable_Output_Data_String)
                    File_Output.close()
                    print(str(datetime.datetime.now()) + " Main file appended.")

                else:
                    sys.exit(str(datetime.datetime.now()) + " No new data has been discovered, no point continuing.")

            else:
                File_Output = open(Complete_File, "w")
                File_Output.write(Output)
                File_Output.close()
                print(str(datetime.datetime.now()) + " Main file created.")

        return Complete_File

    except:
        print(str(datetime.datetime.now()) + " Failed to create file.")

def Data_Type_Discovery(Data_to_Search):
    # Function responsible for determining the type of data found. Examples: Hash_Type, Credentials, Email, or URL.
    Dump_Types = []
    Hash_Types = [["MD5","([a-fA-F0-9]{32})\W"],["SHA1","([a-fA-F0-9]{40})\W"],["SHA256","([a-fA-F0-9]{64})\W"]]

    for Hash_Type in Hash_Types: # Hash_Type identification
        Hash_Regex = re.search(Hash_Type[1], Data_to_Search)

        if Hash_Regex:
            Hash_Type_Line = Hash_Type[0] + " hash"

            if not Hash_Type_Line in Dump_Types:
                Dump_Types.append(Hash_Type_Line)

        else:
            pass

    Credential_Regex = re.search(r"[\w\d\.\-\_]+\@[\w\.]+\:.*", Data_to_Search)

    if Credential_Regex: # Credentials identification

        if not "Credentials" in Dump_Types:
            Dump_Types.append("Credentials")

    else:
        EmailRegex = re.search("[\w\d\.\-\_]+\@[\w\.]+", Data_to_Search)
        URLRegex = re.search("(https?:\/\/(www\.)?)?([-a-zA-Z0-9:%._\+#=]{2,256})(\.[a-z]{2,6}\b([-a-zA-Z0-9:%_\+.#?&//=]*))", Data_to_Search)

        if EmailRegex: # Email Identification

            if not "Email" in Dump_Types:
                Dump_Types.append("Email")

        if URLRegex: # URL Indentification

            if not "URL" in Dump_Types:
                Dump_Types.append("URL")

    return Dump_Types

def Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Output_Data, Query_Result_Name, The_File_Extension):

    for Character in Bad_Characters:

        if Character in Query:
            Query = Query.replace(Character, "")

    try:
        The_File = Plugin_Name + "-Query-" + Query + "-" + Query_Result_Name + The_File_Extension
        Complete_File = os.path.join(Directory, The_File)

        if not os.path.exists(Complete_File):

            with open(Complete_File, 'w') as Current_Output_file:
                Current_Output_file.write(Output_Data)

            print(str(datetime.datetime.now()) + " File: " + Complete_File + " created.")

        else:
            print(str(datetime.datetime.now()) + " File already exists, skipping creation.")

        return Complete_File

    except:
        print(str(datetime.datetime.now()) + " Failed to create file.")

def Create_Scrape_Results_File(Directory, Plugin_Name, Output_Data, ID, The_File_Extension):

    try:
        The_File = Plugin_Name + "-" + ID + The_File_Extension
        Complete_File = os.path.join(Directory, The_File)

        if not os.path.exists(Complete_File):

            with open(Complete_File, 'w') as Current_Output_file:
                Current_Output_file.write(Output_Data)

            print(str(datetime.datetime.now()) + " File: " + Complete_File + " created.")
            return Complete_File

        else:
            print(str(datetime.datetime.now()) + " File already exists, skipping creation.")

    except:
        print(str(datetime.datetime.now()) + " Failed to create file.")

def Load_Location_Configuration():
    Valid_Locations = ['ac', 'ac', 'ad', 'ae', 'af', 'af', 'ag', 'ag', 'ai', 'ai', 'al', 'am', 'am', 'ao', 'aq', 'ar', 'as', 'at', 'au', 'az', 'ba', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bi', 'bj', 'bn', 'bo', 'bo', 'br', 'bs', 'bt', 'bw', 'by', 'by', 'bz', 'ca', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'cn', 'co', 'co', 'co', 'cr', 'cu', 'cv', 'cy', 'cz', 'de', 'dj', 'dk', 'dm', 'do', 'dz', 'ec', 'ec', 'ee', 'eg', 'es', 'et', 'eu', 'fi', 'fj', 'fm', 'fr', 'ga', 'ge', 'ge', 'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gp', 'gp', 'gr', 'gr', 'gt', 'gy', 'gy', 'gy', 'hk', 'hk', 'hn', 'hr', 'ht', 'ht', 'hu', 'hu', 'id', 'id', 'ie', 'il', 'im', 'im', 'in', 'in', 'io', 'iq', 'iq', 'is', 'it', 'je', 'je', 'jm', 'jo', 'jo', 'jp', 'jp', 'ke', 'kg', 'kh', 'ki', 'kr', 'kw', 'kz', 'kz', 'la', 'lb', 'lc', 'li', 'lk', 'ls', 'lt', 'lu', 'lv', 'ly', 'ma', 'ma', 'md', 'me', 'mg', 'mk', 'ml', 'mm', 'mn', 'ms', 'mt', 'mu', 'mv', 'mw', 'mx', 'mx', 'my', 'mz', 'na', 'ne', 'nf', 'ng', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nr', 'nu', 'nz', 'om', 'pa', 'pe', 'pe', 'pf', 'pg', 'ph', 'pk', 'pk', 'pl', 'pl', 'pn', 'pr', 'ps', 'ps', 'pt', 'py', 'qa', 'qa', 're', 'ro', 'rs', 'rs', 'ru', 'ru', 'rw', 'sa', 'sb', 'sc', 'se', 'sg', 'sh', 'si', 'sk', 'sl', 'sl', 'sm', 'sn', 'so', 'sr', 'st', 'sv', 'sy', 'td', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tt', 'tz', 'ua', 'ua', 'ug', 'uk', 'us', 'us', 'uy', 'uz', 'uz', 'vc', 've', 've', 'vg', 'vi', 'vn', 'vu', 'ws', 'za', 'zm', 'zw']

    try:
        Configuration_File = os.path.join('plugins/common/configuration', 'config.json')
        with open(Configuration_File) as JSON_File:  
            Configuration_Data = json.load(JSON_File)

            for General_Details in Configuration_Data['general']:
                Location = General_Details['location']

            if (len(Location) > 2) or (Location not in Valid_Locations):
                sys.exit(str(datetime.datetime.now()) + " An invalid location has been specified, please provide a valid location in the config.json file.")

            else:
                print(str(datetime.datetime.now()) + " Country code " + Location + " selected.")
                return Location

    except:
        sys.exit(str(datetime.datetime.now()) + " Failed to load location details.")

def Make_Directory(Plugin_Name):
    Today = datetime.datetime.now()
    Year = str(Today.year)
    Month = str(Today.month)
    Day = str(Today.day)

    if len(Month) == 1:
        Month = "0" + Month

    if len(Day) == 1:
        Day = "0" + Day

    File_Path = os.path.dirname(os.path.realpath('__file__'))
    Directory = File_Path + "/static/protected/output/" + Plugin_Name + "/" + Year + "/" + Month + "/" + Day

    try:
        os.makedirs(Directory)
        print(str(datetime.datetime.now()) + " Using directory: " + Directory + ".")
        return Directory

    except:
        print(str(datetime.datetime.now()) + " Using directory: " + Directory + ".")
        return Directory

def Get_Latest_URLs(Pull_URL, Scrape_Regex_URL, Is_Tor):
    Scrape_URLs = []
    Content = ""
    Content_String = ""
    Current_Content = ""

    try:
        if Is_Tor:
            print(str(datetime.datetime.now()) + " Querying Tor.")
            Tor_Session.proxies['http'] = 'socks5h://' + Tor_Host + ':' + Tor_Port
            Tor_Session.proxies['https'] = 'socks5h://' + Tor_Host + ':' + Tor_Port
            Content = Tor_Session.get(Pull_URL, Tor_Session_Headers=Tor_Session_Headers).text
            Content_String = str(Content)

        else:
            Content = requests.get(Pull_URL).text
            Content_String = str(Content)

    except:
        sys.exit(str(datetime.datetime.now()) + " Failed to connect, if you are using the Tor network, please make sure you're running the Tor proxy and are connected to it.")

    try:
        Scrape_URLs_Raw = re.findall(Scrape_Regex_URL, Content_String)
        print(str(datetime.datetime.now()) + Scrape_URLs_Raw)
        for Temp_URL_Extensions in Scrape_URLs_Raw:

            if not Temp_URL_Extensions in Scrape_URLs:
                Scrape_URLs.append(Temp_URL_Extensions)

    except:
        sys.exit(str(datetime.datetime.now()) + " Failed to regex URLs.")

    return Scrape_URLs

# def Query_Existing_Files(File_Query, Query_Output_File):
#     # Function to query existing files for new clients.

#     for Bad_Character in Bad_Characters:

#         if Bad_Character in File_Query:
#             sys.exit(str(datetime.datetime.now()) + " Bad Characters found in query. Please remove any conflicting special characters.")

#     os.system(' grep -Hrn ' + File_Query + ' * > ' + Query_Output_File)

#     try:
#         Current_File = open(Query_File, "r")
#         Query_Inputs = Current_File.read().splitlines()
#         Current_File.close()

#     except:
#         sys.exit(str(datetime.datetime.now()) + " Failed to open file.")

#     for Query_Input in Query_Inputs:
#         Query_Input_Regex = re.search(r"(.*\.txt)\:(\d+)\:(.*)", Query_Input)

#         if Query_Input_Regex:
#             print(str(datetime.datetime.now()) + " The query " + File_Query + " was found on line: " + Query_Input_Regex.group(2) + " of file: " + Query_Input_Regex.group(1) + ".")

def Get_Title(URL):

    try:

        if 'file:/' not in URL:
            Soup = BeautifulSoup(urllib.request.urlopen(URL), features="lxml")
            return Soup.title.text

        else:
            print(str(datetime.datetime.now()) + " this function does not work on files.")

    except:
        print(str(datetime.datetime.now()) + " failed to get title.")