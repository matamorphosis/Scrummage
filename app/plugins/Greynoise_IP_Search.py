#!/usr/bin/env python3
import requests, os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID):
        self.Plugin_Name = "Greynoise IP"
        self.Concat_Plugin_Name = "greynoise"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "greynoise.io"
        self.Result_Type = "IP Address Information"

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Concat_Plugin_Name, Details_to_Load=["api_key"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, self.Concat_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            API_Key = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if Common.Regex_Handler(Query, Type="IP"):
                    URL = f"https://api.{self.Domain}/v3/community/{Query}"
                    headers = {"Accept": "application/json"}

                    if type(API_Key) == str and len(API_Key) > 0:
                        headers["key"] = API_Key
                        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Using provided API Key for search.")

                    else:
                        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - No API Key provided, using community edition for search.")

                    Registration_Response_Full = Common.Request_Handler(URL, Optional_Headers=headers, Full_Response=True)
                    JSON_Object = Common.JSON_Handler(Registration_Response_Full.text)
                    Registration_Response = JSON_Object.To_JSON_Loads()
                    Indented_Registration_Response = JSON_Object.Dump_JSON()
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Indented_Registration_Response, Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)

                    if Registration_Response_Full.ok:

                        try:
                            Title = f"Greynoise IP Search | {Query}"
                            Search_Result_Responses = Common.Request_Handler(Registration_Response["link"], Filter=True, Host=f"https://viz.{self.Domain}")
                            Search_Result_Response = Search_Result_Responses["Filtered"]

                            if URL not in Cached_Data and URL not in Data_to_Cache:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Search_Result_Response, Title.replace(" ", "-"), self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], URL, Title, self.Concat_Plugin_Name)
                                    Data_to_Cache.append(URL)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        except:
                            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - No result found for given query {Query}.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Received an invalid response from the API.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - The provided query is not a valid IP address.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")