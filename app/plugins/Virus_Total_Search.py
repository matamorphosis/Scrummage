#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging
from googleapiclient import discovery

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type):
        self.Plugin_Name = "VirusTotal"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "virustotal.com"
        self.Type = Type

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
            Log_File = General.Logging(Directory, self.Plugin_Name.lower())
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            VT_API_Key = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if self.Type == "Domain":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        Response = Common.Request_Handler(f"https://www.{self.Domain}/api/v3/domains/{Query}", Optional_Headers={"x-apikey": VT_API_Key}, Full_Response=True)

                        if Response.status_code == 200:
                            JSON_Object = Common.JSON_Handler(Response.text)
                            JSON_Object.To_JSON_Loads()
                            JSON_Output_Response = JSON_Object.Dump_JSON()
                            Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Domain Information", self.Task_ID, self.Plugin_Name.lower())
                            Link = f"https://www.{self.Domain}/gui/self.Domain/{Query}/detection"
                            Main_URL_Responses = Common.Request_Handler(Link, Filter=True, Host=f"https://www.{self.Domain}")
                            Main_URL_Response = Main_URL_Responses["Filtered"]
                            Title = f"Virus Total self.Domain | {Query}"

                            if Link not in Cached_Data and Link not in Data_to_Cache:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name.lower(), Main_URL_Response, Link, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Link, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Link)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                elif self.Type == "IP":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        Response = Common.Request_Handler(f"https://www.{self.Domain}/api/v3/ip_addresses/{Query}", Optional_Headers={"x-apikey": VT_API_Key}, Full_Response=True)

                        if Response.status_code == 200:
                            JSON_Object = Common.JSON_Handler(Response.text)
                            JSON_Object.To_JSON_Loads()
                            JSON_Output_Response = JSON_Object.Dump_JSON()
                            Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "IP Address Information", self.Task_ID, self.Plugin_Name.lower())
                            Link = f"https://www.{self.Domain}/gui/ip-address/{Query}/detection"
                            Main_URL_Responses = Common.Request_Handler(Link, Filter=True, Host=f"https://www.{self.Domain}")
                            Main_URL_Response = Main_URL_Responses["Filtered"]
                            Title = f"Virus Total IP Address | {Query}"

                            if Link not in Cached_Data and Link not in Data_to_Cache:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name.lower(), Main_URL_Response, Link, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Link, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Link)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                elif self.Type == "URL":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        import base64
                        Query_Encoded = base64.urlsafe_b64encode(Query.encode()).decode().strip("=")
                        Response = Common.Request_Handler(f"https://www.{self.Domain}/api/v3/urls/{Query_Encoded}", Optional_Headers={"x-apikey": VT_API_Key}, Full_Response=True)

                        if Response.status_code == 200:
                            JSON_Object = Common.JSON_Handler(Response.text)
                            JSON_Object.To_JSON_Loads()
                            JSON_Output_Response = JSON_Object.Dump_JSON()
                            Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Domain Information", self.Task_ID, self.Plugin_Name.lower())
                            Link = f"https://www.{self.Domain}/gui/url/{Query_Encoded}/detection"
                            Main_URL_Responses = Common.Request_Handler(Link, Filter=True, Host=f"https://www.{self.Domain}")
                            Main_URL_Response = Main_URL_Responses["Filtered"]
                            Title = f"Virus Total URL | {Query}"

                            if Link not in Cached_Data and Link not in Data_to_Cache:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name.lower(), Main_URL_Response, Link, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Link, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Link)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                elif self.Type == "Hash":
                    Response = Common.Request_Handler(f"https://www.{self.Domain}/api/v3/files/{Query}", Optional_Headers={"x-apikey": VT_API_Key}, Full_Response=True)

                    if Response.status_code == 200:
                        JSON_Object = Common.JSON_Handler(Response.text)
                        JSON_Object.To_JSON_Loads()
                        JSON_Output_Response = JSON_Object.Dump_JSON()
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Virus", self.Task_ID, self.Plugin_Name.lower())
                        Link = f"https://www.{self.Domain}/gui/file/{Query}/detection"
                        Main_URL_Responses = Common.Request_Handler(Link, Filter=True, Host=f"https://www.{self.Domain}")
                        Main_URL_Response = Main_URL_Responses["Filtered"]
                        Title = f"Virus Total File | {Query}"

                        if Link not in Cached_Data and Link not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name.lower(), Main_URL_Response, Link, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Link, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Link)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")