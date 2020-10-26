#!/usr/bin/env python3
import plugins.common.General as General, requests, json, os, logging
from googleapiclient import discovery

The_File_Extensions = {"Main": ".json", "Query": ".html"}
Plugin_Name = "YouTube"
Domain = "youtube.com"
headers = General.URL_Headers(User_Agent=True)

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:  
            Configuration_Data = json.load(JSON_File)
            YouTube_Details = Configuration_Data[Plugin_Name.lower()]
            YouTube_Developer_Key = YouTube_Details['developer_key']
            YouTube_Application_Name = YouTube_Details['application_name']
            YouTube_Application_Version = YouTube_Details['application_version']
            YouTube_Location = YouTube_Details['location']
            YouTube_Location_Radius = YouTube_Details['location_radius']

            if YouTube_Developer_Key and YouTube_Application_Name and YouTube_Application_Version:
                return [YouTube_Developer_Key, YouTube_Application_Name, YouTube_Application_Version, YouTube_Location, YouTube_Location_Radius]

            else:
                return None

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to load location details.")

def Search(Query_List, Task_ID, **kwargs):

    try:
        Data_to_Cache = []
        Directory = General.Make_Directory(Plugin_Name.lower())
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        Log_File = General.Logging(Directory, Plugin_Name.lower())
        handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        YouTube_Details = Load_Configuration()
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:
            YouTube_Handler = discovery.build(YouTube_Details[1], YouTube_Details[2], developerKey=YouTube_Details[0], cache_discovery=False)

            if YouTube_Details[3] and YouTube_Details[4]:
                Search_Response = YouTube_Handler.search().list(q=Query, type='video', location=YouTube_Details[3], locationRadius=YouTube_Details[4], part='id,snippet', maxResults=Limit,).execute()

            else:
                Search_Response = YouTube_Handler.search().list(q=Query, type='video', part='id,snippet', maxResults=Limit,).execute()
            
            Main_File = General.Main_File_Create(Directory, Plugin_Name, json.dumps(Search_Response.get('items', []), indent=4, sort_keys=True), Query, The_File_Extensions["Main"])
            Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Social Media - Media", Task_ID, Plugin_Name.lower())

            for Search_Result in Search_Response.get('items', []):
                Full_Video_URL = f"https://www.{Domain}/watch?v=" + Search_Result['id']['videoId']
                Search_Video_Response = requests.get(Full_Video_URL, headers=headers).text
                Search_Video_Response = General.Response_Filter(Search_Video_Response, f"https://www.{Domain}")
                Title = "YouTube | " + Search_Result['snippet']['title']

                if Full_Video_URL not in Cached_Data and Full_Video_URL not in Data_to_Cache:
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Search_Video_Response, Search_Result['id']['videoId'], The_File_Extensions["Query"])

                    if Output_file:
                        Output_Connections.Output([Main_File, Output_file], Full_Video_URL, Title, Plugin_Name.lower())
                        Data_to_Cache.append(Full_Video_URL)

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")