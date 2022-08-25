#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "LeakIX"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "leakix.net"
        self.Result_Type: str = "Data Leakage"
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
                Current_Step = 0
                Response = Common.Request_Handler(url=f"https://{self.Domain}/search?q={Query}&scope=leak", Application_JSON_Accept=True)
                JSON_Object = Common.JSON_Handler(Response)
                JSON_Response = JSON_Object.To_JSON_Loads()
                JSON_Output_Response = JSON_Object.Dump_JSON()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                for Search_Result in JSON_Response:
                    Host = Search_Result["ip"]
                    Result_Title = f"{self.Plugin_Name} Host | {Common.Fang().Defang(Host)}"
                    Result_URL = f"https://{self.Domain}/host/{Host}"
                    Search_Result_Responses = Common.Request_Handler(url=Result_URL, Filter=True, Host=f"https://{self.Domain}")
                    Search_Result_Response = Search_Result_Responses["Filtered"]

                    if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Search_Result_Response, Result_Title, self.The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Result_URL, Result_Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(Result_URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        Current_Step += 1

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")