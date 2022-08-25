#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Plugin_Name: str = "Doing Business"
        self.Concat_Plugin_Name: str = "doingbusiness"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "doingbusiness.org"
        self.Result_Type: str = "Economic Details"

    def Search(self):

        try:
            Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Concat_Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Headers_Custom = {"Referer": "https://www.doingbusiness.org/", "Ocp-Apim-Subscription-Key": "7c202aad75524b5a9c9f0a9fa42cbbbc"}
                Main_URL = f"https://wbgindicators.azure-api.net/DoingBusiness/api/GetEconomyByURL/{Query}"
                Doing_Business_Response = Common.Request_Handler(url=Main_URL, Optional_Headers=Headers_Custom)
                JSON_Object = Common.JSON_Handler(Doing_Business_Response)
                JSON_Response = JSON_Object.To_JSON_Loads()
                JSON_Output_Response = JSON_Object.Dump_JSON()

                if 'message' not in JSON_Response:
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                    Item_URL = f"https://www.{self.Domain}/en/data/exploreeconomies/{Query}"
                    Title = f"{self.Plugin_Name} | {Query}"
                    Current_Doing_Business_Responses = Common.Request_Handler(url=Item_URL, Filter=True, Host=f"https://www.{self.Domain}")
                    Current_Doing_Business_Response = Current_Doing_Business_Responses["Filtered"]

                    if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Current_Doing_Business_Response, Query, self.The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)
                            Output_Connections.Output([Main_File, Output_file], Item_URL, Title, self.Concat_Plugin_Name)
                            Data_to_Cache.append(Item_URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid JSON response received.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f'{Common.Date()} - {self.Logging_Plugin_Name} - {e}')