#!/usr/bin/env python3
import plugins.common.General as General, datetime, requests, sys, json, os
from googleapiclient import discovery

YouTube_Developer_Key = ""
YouTube_Application_Name = ""
YouTube_Application_Version = ""
YouTube_Location = ""
YouTube_Location_Radius = ""

The_File_Extension = ".html"
Plugin_Name = "YouTube"

def Load_Configuration():
    global YouTube_Developer_Key
    global YouTube_Application_Name
    global YouTube_Application_Version
    global YouTube_Location
    global YouTube_Location_Radius
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/configuration/config.json')
    print(str(datetime.datetime.now()) + " Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:  
            Configuration_Data = json.load(JSON_File)

            for YouTube_Details in Configuration_Data[Plugin_Name.lower()]:
                YouTube_Developer_Key = YouTube_Details['developer_key']
                YouTube_Application_Name = YouTube_Details['application_name']
                YouTube_Application_Version = YouTube_Details['application_version']
                YouTube_Location = YouTube_Details['location']
                YouTube_Location_Radius = YouTube_Details['location_radius']

    except:
        sys.exit(str(datetime.datetime.now()) + " Failed to load location details.")

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if int(kwargs["Limit"]) > 0:
        Limit = kwargs["Limit"]

    else:
        Limit = 25

    Directory = General.Make_Directory(Plugin_Name.lower())
    General.Logging(Directory, Plugin_Name)
    Load_Configuration()
    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:
        YouTube_Handler = discovery.build(YouTube_Application_Name, YouTube_Application_Version, developerKey=YouTube_Developer_Key)
        Search_Response = YouTube_Handler.search().list(
        q=Query,
        type='video',
        location=YouTube_Location,
        locationRadius=YouTube_Location_Radius,
        part='id,snippet',
        maxResults=Limit,
        ).execute()
        General.Main_File_Create(Directory, Plugin_Name, json.dumps(Search_Response.get('items', []), indent=4, sort_keys=True), Query, ".json")

        for Search_Result in Search_Response.get('items', []):
            Full_Video_URL = "https://www.youtube.com/watch?v=" + Search_Result['id']['videoId']
            Search_Video_Response = requests.get(Full_Video_URL).text

            if Full_Video_URL not in Cached_Data and Full_Video_URL not in Data_to_Cache:
                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Search_Video_Response, Search_Result['id']['videoId'], The_File_Extension)

                if Output_file:
                    General.Connections(Output_file, Query, Plugin_Name, Full_Video_URL, "youtube.com", "Data Leakage", Task_ID, General.Get_Title(Full_Video_URL))

                Data_to_Cache.append(Full_Video_URL)

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")