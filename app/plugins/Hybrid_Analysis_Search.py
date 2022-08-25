#!/usr/bin/env python3
import os, logging, urllib.parse, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Plugin_Name: str = "Hybrid Analysis"
        self.Concat_Plugin_Name: str = "hybridanalysis"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "hybrid-analysis.com"
        self.Result_Type: str = "Domain Information"

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Concat_Plugin_Name, Details_to_Load=["api_key"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:
            Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, self.Concat_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            API_Key = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if Common.Regex_Handler(Query, Type="Domain"):
                    API_URL = f"https://www.{self.Domain}/api/v2/quick-scan/url"
                    Headers = {"api-key": API_Key}
                    URL_Query = urllib.parse.quote_plus(Query)
                    Data = {"scan_type": "all", "url": URL_Query}
                    Response = Common.Request_Handler(url=API_URL, method="POST", Application_JSON_Accept=True, Application_Form_CT=True, Data=Data, Optional_Headers=Headers)
                    JSON_Object = Common.JSON_Handler(Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    Standard_URL = f"https://www.{self.Domain}/search?query={URL_Query}"
                    Responses = Common.Request_Handler(url=Standard_URL, Filter=True, Host=f"https://www.{self.Domain}")
                    Response = Responses["Filtered"]
                    Main_File = General.Main_File_Create(Directory, self.Concat_Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                    if "id" in JSON_Response and API_URL not in Cached_Data and API_URL not in Data_to_Cache:
                        Title = f"{self.Plugin_Name} | {Common.Fang().Defang(Query)}"
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Concat_Plugin_Name, Response, Title, self.The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], API_URL, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(API_URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")