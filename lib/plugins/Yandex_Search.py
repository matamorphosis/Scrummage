#!/usr/bin/env python3
import logging, os, xmltodict, json, plugins.common.General as General

Plugin_Name = "Yandex"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "yandex.com"

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:  
            Configuration_Data = json.load(JSON_File)
            Yandex_Details = Configuration_Data[Plugin_Name.lower()]
            Yandex_User = Yandex_Details['username']
            Yandex_API_Key = Yandex_Details['api_key']

            if Yandex_User and Yandex_API_Key:
                return [Yandex_User, Yandex_API_Key]

            else:
                return None

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to load API details.")

def Recursive_Dict_Check(Items, Dict_to_Check):

    try:

        for Item in Items:

            if Item in Dict_to_Check:
                Dict_to_Check = Dict_to_Check[Item]

            else:
                return False

        return Dict_to_Check

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")

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
        Yandex_Details = Load_Configuration()
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:
            Yandex_Response = General.Request_Handler(f"https://{Domain}/search/xml?user={Yandex_Details[0]}&key={Yandex_Details[1]}&query={Query}&l10n=en&sortby=rlv&filter=none&maxpassages=five&groupby=attr% 3D% 22% 22.mode% 3Dflat.groups-on-page% 3D{str(Limit)}.docs-in-group% 3D1")
            JSON_Response = xmltodict.parse(Yandex_Response)
            JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
            Main_File = General.Main_File_Create(Directory, Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
            Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Search Result", Task_ID, Plugin_Name.lower())
            New_JSON_Response = Recursive_Dict_Check(["yandexsearch", "response", "results", "grouping", "group"], JSON_Response)

            if New_JSON_Response:

                for Yandex_Item_Line in New_JSON_Response:

                    try:

                        if Recursive_Dict_Check(["doc", "url"], Yandex_Item_Line):
                            Yandex_Item_Line = Yandex_Item_Line['doc']
                            Yandex_URL = Yandex_Item_Line['url']
                            Title = Recursive_Dict_Check(["title", "#text"], JSON_Response)

                            if Title:
                                Title = f"Yandex | {Title}"

                            else:
                                Title = General.Get_Title(Yandex_URL)
                                Title = f"Yandex | {Title}"

                            if Yandex_URL not in Cached_Data and Yandex_URL not in Data_to_Cache:
                                Yandex_Item_Responses = General.Request_Handler(Yandex_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://{Domain}")
                                Yandex_Item_Response = Yandex_Item_Responses["Filtered"]
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Yandex_Item_Response, Yandex_URL, The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Yandex_URL, Title, Plugin_Name.lower())
                                    Data_to_Cache.append(Yandex_URL)

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                    except Exception as e:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - No results found.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")