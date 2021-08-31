#!/usr/bin/env python3
# Version 2 of Plugin. Version 1 relied on an unstable HeroApp API, version 2 uses the unofficial py1337x library.
import plugins.common.General as General, plugins.common.Common as Common, os, logging
from py1337x import py1337x

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Torrent"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "1337x.to"
        self.Result_Type = "Torrent"
        self.Limit = General.Get_Limit(Limit)

    def Search(self):

        try:
            Data_to_Cache = []
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
                Torrents = py1337x(proxy='1337x.tw')
                Results = Torrents.search(Query)
                JSON_Response = Common.JSON_Handler(Results).Dump_JSON()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Response, Query, self.The_File_Extensions["Main"])
                Current_Step = 0
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                if 'items' in Results and len(Results['items']) > 0:
                
                    for Search_Result in Results['items']:
                        Result_Title = f"{self.Plugin_Name} | " + Search_Result["name"]
                        Result_URL = Search_Result["link"]

                        if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, JSON_Response, Result_Title, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Result_URL, General.Get_Title(Result_URL), self.Plugin_Name.lower())
                                Data_to_Cache.append(Result_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            Current_Step += 1

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")