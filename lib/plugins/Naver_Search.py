#!/usr/bin/env python3
import logging, os, json, urllib.parse, plugins.common.General as General

Plugin_Name = "Naver"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "naver.com"

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:  
            Configuration_Data = json.load(JSON_File)
            Naver_Details = Configuration_Data[Plugin_Name.lower()]
            Naver_Client_ID = Naver_Details['client_id']
            Naver_Client_Secret = Naver_Details['client_secret']

            if Naver_Client_ID and Naver_Client_Secret:
                return [Naver_Client_ID, Naver_Client_Secret]

            else:
                return None

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to load API details.")

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
        Naver_Details = Load_Configuration()
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        if int(Limit) > 100:
            logging.fatal(f"{General.Date()} - {__name__.strip('plugins.')} - This plugin does not support limits over 100.")
            return None

        for Query in Query_List:
            URL_Query = urllib.parse.quote(Query)
            URL = f"https://openapi.{Domain}/v1/search/webkr.json?query={URL_Query}&display={str(Limit)}&sort=sim"
            Headers = {"X-Naver-Client-Id": Naver_Details[0], "X-Naver-Client-Secret": Naver_Details[1]}
            Naver_Response = General.Request_Handler(URL, Optional_Headers=Headers)
            JSON_Response = json.loads(Naver_Response)
            JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
            Main_File = General.Main_File_Create(Directory, Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
            Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Search Result", Task_ID, Plugin_Name.lower())

            if JSON_Response.get('items'):

                for Naver_Item_Link in JSON_Response['items']:

                    try:

                        if 'title' in Naver_Item_Link and 'link' in Naver_Item_Link:
                            Naver_URL = Naver_Item_Link['link']
                            Title = Naver_Item_Link['title']
                            Title = f"Naver | {Title}"

                            if Naver_URL not in Cached_Data and Naver_URL not in Data_to_Cache:
                                Naver_Item_Responses = General.Request_Handler(Naver_URL, Filter=True, Host=f"https://www.{Domain}")
                                Naver_Item_Response = Naver_Item_Responses["Filtered"]
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Naver_Item_Response, Naver_URL, The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Naver_URL, Title, Plugin_Name.lower())
                                    Data_to_Cache.append(Naver_URL)

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                    except Exception as e:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - No results found.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")