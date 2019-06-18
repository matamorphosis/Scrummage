#!/usr/bin/env python3
import requests, re, os, sys, json, datetime, plugins.common.General as General
from googleapiclient.discovery import build

Plugin_Name = "Google"
The_File_Extension = ".html"
Google_CX = ""
Google_Developer_Key = ""
Google_Application_Name = ""
Google_Application_Version = ""

def Load_Configuration():
    global Google_CX
    global Google_Developer_Key
    global Google_Application_Name
    global Google_Application_Version
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/configuration/config.json')
    print(str(datetime.datetime.now()) + " Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:  
            Configuration_Data = json.load(JSON_File)

            for Google_Details in Configuration_Data[Plugin_Name.lower()]:
                Google_CX = Google_Details['cx']
                Google_Developer_Key = Google_Details['developer_key']
                Google_Application_Name = Google_Details['application_name']
                Google_Application_Version = Google_Details['application_version']

    except:
        sys.exit(str(datetime.datetime.now()) + " Failed to load location details.")

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if int(kwargs["Limit"]) > 0:
        Limit = kwargs["Limit"]

    else:
        Limit = 10

    Directory = General.Make_Directory(Plugin_Name.lower())
    General.Logging(Directory, Plugin_Name)
    Load_Configuration()
    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:
        Service = build("customsearch", Google_Application_Version, developerKey=Google_Developer_Key)
        CSE_Response = Service.cse().list(q=Query, cx=Google_CX, num=Limit).execute()
        CSE_JSON_Output_Response = json.dumps(CSE_Response, indent=4, sort_keys=True)
        CSE_JSON_Response = json.loads(CSE_JSON_Output_Response)

        General.Main_File_Create(Directory, Plugin_Name, CSE_JSON_Output_Response, Query, ".json")

        for JSON_Response_Items in CSE_JSON_Response['items']:

            try:
                Google_Item = JSON_Response_Items['pagemap']['metatags']

                for Google_Item_Line in Google_Item:
                    Google_Item_URL = Google_Item_Line['og:url']

                    if Google_Item_URL not in Cached_Data and Google_Item_URL not in Data_to_Cache:
                        Path_Regex = re.search(r"https?\:\/\/(www\.)?[\w\d\.]+\.\w{2,3}(\.\w{2,3})?(\.\w{2,3})?\/([\w\d\-\_\/]+)?", Google_Item_URL)

                        if Path_Regex:
                            headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0', 'Accept': 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}
                            Google_Item_Response = requests.get(Google_Item_URL, headers=headers).text
                            Output_Path = Path_Regex.group(4).replace("/", "-")
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Google_Item_Response, Output_Path, The_File_Extension)

                            if Output_file:
                                General.Connections(Output_file, Query, Plugin_Name, Google_Item_URL, "google.com", "Domain Spoof", Task_ID, General.Get_Title(Google_Item_URL))

                        Data_to_Cache.append(Google_Item_URL)


            except Exception as e:
                print(str(datetime.datetime.now()) + e)

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")