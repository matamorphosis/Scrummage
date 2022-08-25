#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Plugin_Name: str = "WhatCMS"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "whatcms.org"
        self.Result_Type: str = "Web Application Architecture"

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["api_key"])

        if Result:
            return Result

        else:
            return None

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
            API_Key = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Search_URL = f"https://{self.Domain}/API/Tech?key={API_Key}&url={Query}"
                HTML_URL = f"https://{self.Domain}/?s={Query}"
                Response = Common.Request_Handler(url=Search_URL)
                JSON_Object = Common.JSON_Handler(Response)
                JSON_Response = JSON_Object.To_JSON_Loads()
                JSON_Output_Response = JSON_Object.Dump_JSON()
                HTML_Responses = Common.Request_Handler(url=HTML_URL, Filter=True, Host=f"https://{self.Domain}")
                Filtered_Response = HTML_Responses["Filtered"]
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                if JSON_Response.get("results") and len(JSON_Response["results"]) > 0:

                    if HTML_URL not in Cached_Data and HTML_URL not in Data_to_Cache:
                        Title = f"{self.Plugin_Name} | {Common.Fang().Defang(Query)}"
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Filtered_Response, Query, self.The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], HTML_URL, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(HTML_URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")