#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "URLScan"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "urlscan.io"
        self.Result_Type = "Domain Information"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["api_key"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name.lower())), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            API_Key = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            if int(self.Limit) > 100:
                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - This plugin does not support limits over 100, setting limit to 100.")
                self.Limit = 100

            for Query in self.Query_List:
                Domain_Regex = Common.Regex_Handler(Query, Type="Domain")

                if Domain_Regex:
                    URL = f"https://{self.Domain}/api/v1/search/?q=domain:{Query}"
                    Headers = {"API-Key": API_Key}
                    Response = Common.Request_Handler(URL, Optional_Headers=Headers)
                    JSON_Object = Common.JSON_Handler(Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                    if JSON_Response.get('results'):
                        Current_Step = 0

                        for URLScan_Item in JSON_Response['results']:

                            try:
                                URLScan_URL = URLScan_Item['page']['url']
                                Title = f"{self.Plugin_Name} | " + URLScan_Item['task']['uuid']

                                if URLScan_URL not in Cached_Data and URLScan_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                    URLScan_Item_Responses = Common.Request_Handler(URLScan_URL, Filter=True, Host=f"https://{self.Domain}")
                                    URLScan_Item_Response = URLScan_Item_Responses["Filtered"]
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, URLScan_Item_Response, URLScan_URL, self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], URLScan_URL, Title, self.Plugin_Name.lower())
                                        Data_to_Cache.append(URLScan_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                    Current_Step += 1

                            except Exception as e:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")