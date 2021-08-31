#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type):
        self.Plugin_Name = "Alienvault OTX"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "otx.alienvault.com"
        self.Type = Type

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, self.Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if self.Type == "Domain":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        API_URL = f"https://{self.Domain}/otxapi/indicators/domain/http_scans/{Query}"
                        JSON_Response = Common.Request_Handler(API_URL)
                        JSON_Object = Common.JSON_Handler(JSON_Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()
                        JSON_Output_Response = JSON_Object.Dump_JSON()

                        if not JSON_Response.get("Error"):
                            Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Domain Information", self.Task_ID, self.Plugin_Name.lower())

                            if Query not in Cached_Data and Query not in Data_to_Cache:
                                Search_URL = f"https://{self.Domain}/indicator/domain/{Query}"
                                Responses = Common.Request_Handler(Search_URL, Filter=True, Host=f"https://{self.Domain}")
                                Response = Responses["Filtered"]
                                Title = f"{self.Plugin_Name} {self.Type} | {Query}"
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, Title, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Search_URL, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Query)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Domain doesn't exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

                elif self.Type == "IP":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        API_URL = f"https://{self.Domain}/otxapi/indicators/IPv4/http_scans/{Query}"
                        JSON_Response = Common.Request_Handler(API_URL)
                        JSON_Object = Common.JSON_Handler(JSON_Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()
                        JSON_Output_Response = JSON_Object.Dump_JSON()

                        if not JSON_Response.get("Error"):
                            Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "IP Address Information", self.Task_ID, self.Plugin_Name.lower())

                            if Query not in Cached_Data and Query not in Data_to_Cache:
                                Search_URL = f"https://{self.Domain}/indicator/domain/{Query}"
                                Responses = Common.Request_Handler(Search_URL, Filter=True, Host=f"https://{self.Domain}")
                                Response = Responses["Filtered"]
                                Title = f"{self.Plugin_Name} {self.Type} | {Query}"
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, Title, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Search_URL, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Query)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - IP Address doesn't exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid type provided.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")