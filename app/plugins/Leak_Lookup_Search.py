#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Type: str = str()):
        self.Plugin_Name: str = "Leak Lookup"
        self.Concat_Plugin_Name: str = "leaklookup"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "leak-lookup.com"
        self.Type = Type

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

                if self.Type == "Email":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        URL = f"https://{self.Domain}/api/search"
                        Data = {"key": API_Key, "type": "email_address", "query": Query}
                        Response = Common.Request_Handler(url=URL, Data=Data)
                        JSON_Object = Common.JSON_Handler(Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()
                        JSON_Output_Response = JSON_Object.Dump_JSON()
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Email Information", self.Task_ID, self.Concat_Plugin_Name)

                        if JSON_Response.get("error") == "false":
                            
                            if Query not in Cached_Data and Query not in Data_to_Cache:
                                Data = f"search-type%5B%5D=1&search-type%5B%5D=2&query={Query}"
                                Item_URL = f"https://{self.Domain}/search"
                                Item_Responses = Common.Request_Handler(url=Item_URL, method="POST", Data=Data, Filter=True, Host=f"https://{self.Domain}")
                                Output_Response = Item_Responses["Filtered"]
                                Title = f"{self.Plugin_Name} {self.Type} | {Common.Fang().Defang(Query)}"
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Output_Response, Title, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Item_URL, Title, self.Concat_Plugin_Name)
                                    Data_to_Cache.append(Query)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

                elif self.Type == "Username":
                    URL = f"https://{self.Domain}/api/search"
                    Data = f"search-type%5B%5D=1&search-type%5B%5D=2&query={Query}"
                    Response = Common.Request_Handler(url=URL, Data=Data)
                    JSON_Object = Common.JSON_Handler(Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Account", self.Task_ID, self.Concat_Plugin_Name)

                    if JSON_Response.get("error") == "false":
                        
                        if Query not in Cached_Data and Query not in Data_to_Cache:
                            Data = f"search-type%5B%5D=1&search-type%5B%5D=2&query={Query}"
                            Item_URL = f"https://{self.Domain}/search"
                            Item_Responses = Common.Request_Handler(url=Item_URL, method="POST", Data=Data, Filter=True, Host=f"https://{self.Domain}")
                            Output_Response = Item_Responses["Filtered"]
                            Title = f"{self.Plugin_Name} {self.Type} | {Query}"
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Output_Response, Title, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Item_URL, Title, self.Concat_Plugin_Name)
                                Data_to_Cache.append(Query)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                elif self.Type == "IP":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        URL = f"https://{self.Domain}/api/search"
                        Data = {"key": API_Key, "type": "ipaddress", "query": Query}
                        Response = Common.Request_Handler(url=URL, Data=Data)
                        JSON_Object = Common.JSON_Handler(Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()
                        JSON_Output_Response = JSON_Object.Dump_JSON()
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "IP Address Information", self.Task_ID, self.Concat_Plugin_Name)

                        if JSON_Response.get("error") == "false":
                            
                            if Query not in Cached_Data and Query not in Data_to_Cache:
                                Data = f"search-type%5B%5D=1&search-type%5B%5D=2&query={Query}"
                                Item_URL = f"https://{self.Domain}/search"
                                Item_Responses = Common.Request_Handler(url=Item_URL, method="POST", Data=Data, Filter=True, Host=f"https://{self.Domain}")
                                Output_Response = Item_Responses["Filtered"]
                                Title = f"{self.Plugin_Name} {self.Type} | {Common.Fang().Defang(Query)}"
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Output_Response, Title, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Item_URL, Title, self.Concat_Plugin_Name)
                                    Data_to_Cache.append(Query)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

                elif self.Type == "Domain":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        URL = f"https://{self.Domain}/api/search"
                        Data = {"key": API_Key, "type": "domain", "query": Query}
                        Response = Common.Request_Handler(url=URL, Data=Data)
                        JSON_Object = Common.JSON_Handler(Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()
                        JSON_Output_Response = JSON_Object.Dump_JSON()
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Domain Information", self.Task_ID, self.Concat_Plugin_Name)

                        if JSON_Response.get("error") == "false":
                            
                            if Query not in Cached_Data and Query not in Data_to_Cache:
                                Data = f"search-type%5B%5D=1&search-type%5B%5D=2&query={Query}"
                                Item_URL = f"https://{self.Domain}/search"
                                Item_Responses = Common.Request_Handler(url=Item_URL, method="POST", Data=Data, Filter=True, Host=f"https://{self.Domain}")
                                Output_Response = Item_Responses["Filtered"]
                                Title = f"{self.Plugin_Name} {self.Type} | {Common.Fang().Defang(Query)}"
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Output_Response, Title, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Item_URL, Title, self.Concat_Plugin_Name)
                                    Data_to_Cache.append(Query)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

                elif self.Type == "Hash":

                    if any(Common.Regex_Handler(Query, Type=Hash_Type) for Hash_Type in ["MD5", "SHA1", "SHA256"]):
                        URL = f"https://{self.Domain}/api/search"
                        Data = {"key": API_Key, "type": "hash", "query": Query}
                        Response = Common.Request_Handler(url=URL, Data=Data)
                        JSON_Object = Common.JSON_Handler(Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()
                        JSON_Output_Response = JSON_Object.Dump_JSON()
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Type, self.Task_ID, self.Concat_Plugin_Name)

                        if JSON_Response.get("error") == "false":

                            if Query not in Cached_Data and Query not in Data_to_Cache:
                                Data = f"search-type%5B%5D=1&search-type%5B%5D=2&query={Query}"
                                Item_URL = f"https://{self.Domain}/search"
                                Item_Responses = Common.Request_Handler(url=Item_URL, method="POST", Data=Data, Filter=True, Host=f"https://{self.Domain}")
                                Output_Response = Item_Responses["Filtered"]
                                Title = f"{self.Plugin_Name} {self.Type} | {Query}"
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Output_Response, Title, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Item_URL, Title, self.Concat_Plugin_Name)
                                    Data_to_Cache.append(Query)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid type provided.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")