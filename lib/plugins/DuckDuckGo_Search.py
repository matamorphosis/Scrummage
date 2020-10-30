#!/usr/bin/env python3
import requests, logging, os, json, urllib.parse, plugins.common.General as General

Plugin_Name = "DuckDuckGo"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "duckduckgo.com"

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
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:
            URL_Query = urllib.parse.quote(Query)
            URL = f"https://api.duckduckgo.com/?q={URL_Query}&format=json"
            DDG_Response = General.Request_Handler(URL)
            JSON_Response = json.loads(DDG_Response)
            JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
            Main_File = General.Main_File_Create(Directory, Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
            Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Search Result", Task_ID, Plugin_Name.lower())

            if JSON_Response.get('RelatedTopics'):
                Current_Step = 0

                for DDG_Item_Link in JSON_Response['RelatedTopics']:

                    try:

                        if 'FirstURL' in DDG_Item_Link:
                            DDG_URL = DDG_Item_Link['FirstURL']
                            Title = General.Get_Title(DDG_URL)
                            Title = f"DuckDuckGo | {Title}"

                            if DDG_URL not in Cached_Data and DDG_URL not in Data_to_Cache and Current_Step < int(Limit):
                                DDG_Item_Responses = General.Request_Handler(DDG_URL, Filter=True, Host=f"https://www.{Domain}")
                                DDG_Item_Response = DDG_Item_Responses["Filtered"]
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, DDG_Item_Response, DDG_URL, The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], DDG_URL, Title, Plugin_Name.lower())
                                    Data_to_Cache.append(DDG_URL)

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                                Current_Step += 1

                            else:
                                break

                        elif 'Topics' in DDG_Item_Link:

                            if type(DDG_Item_Link['Topics']) == list:
                                JSON_Response['RelatedTopics'].extend(DDG_Item_Link['Topics'])

                    except Exception as e:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - No results found.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")