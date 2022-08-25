#!/usr/bin/env python3
import logging, os, urllib.parse, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "DuckDuckGo"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "duckduckgo.com"
        self.Result_Type: str = "Search Result"
        self.Limit = General.Get_Limit(Limit)

    def Search(self):

        try:
            Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                URL_Query = urllib.parse.quote(Query)
                URL = f"https://api.{self.Domain}/?q={URL_Query}&format=json"
                DDG_Response = Common.Request_Handler(url=URL)
                JSON_Object = Common.JSON_Handler(DDG_Response)
                JSON_Response = JSON_Object.To_JSON_Loads()
                JSON_Output_Response = JSON_Object.Dump_JSON()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                if JSON_Response.get('RelatedTopics'):
                    Current_Step = 0

                    for DDG_Item_Link in JSON_Response['RelatedTopics']:

                        try:

                            if 'FirstURL' in DDG_Item_Link:
                                DDG_URL = DDG_Item_Link['FirstURL']
                                Title = General.Get_Title(DDG_URL)
                                Title = f"{self.Plugin_Name} | {Title}"

                                if DDG_URL not in Cached_Data and DDG_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                    DDG_Item_Responses = Common.Request_Handler(url=DDG_URL, Filter=True, Host=f"https://www.{self.Domain}")
                                    DDG_Item_Response = DDG_Item_Responses["Filtered"]
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, DDG_Item_Response, DDG_URL, self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], DDG_URL, Title, self.Plugin_Name.lower())
                                        Data_to_Cache.append(DDG_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                    Current_Step += 1

                            elif 'Topics' in DDG_Item_Link:

                                if type(DDG_Item_Link['Topics']) == list:
                                    JSON_Response['RelatedTopics'].extend(DDG_Item_Link['Topics'])

                        except Exception as e:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")