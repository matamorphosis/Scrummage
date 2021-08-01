#!/usr/bin/env python3
# Version 1 of Plugin - Outdated - Replacement underway.
import plugins.common.General as General, plugins.common.Common as Common, os, logging

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Torrent"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".json"
        self.Domain = "thepiratebay.org"
        self.Result_Type = "Torrent"
        self.Limit = General.Get_Limit(Limit)

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, self.Plugin_Name.lower())
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Response = Common.Request_Handler('https://tpbc.herokuapp.com/search/' + Query.replace(" ", "+") + '/?sort=seeds_desc')
                JSON_Object = Common.JSON_Handler(Response)
                Response = JSON_Object.To_JSON_Loads()
                JSON_Response = JSON_Object.Dump_JSON()
                Output_file = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Response, Query, self.The_File_Extension)

                if Output_file:
                    Current_Step = 0
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                    for Search_Result in Response:
                        Result_Title = Search_Result["title"]
                        Result_URL = Search_Result["magnet"]

                        if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, JSON_Response, Result_Title, self.The_File_Extension)

                            if Output_file:
                                Output_Connections.Output([Output_file], Result_URL, General.Get_Title(Result_URL), self.Plugin_Name.lower())
                                Data_to_Cache.append(Result_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            Current_Step += 1

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")