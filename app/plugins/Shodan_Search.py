#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common
from shodan import Shodan

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type, Limit=10):
        self.Plugin_Name = "Shodan"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "shodan.io"
        self.Result_Type = "Domain Information"
        self.Type = Type
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
            Log_File = General.Logging(Directory, self.Plugin_Name.lower())
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            Shodan_API_Key = self.Load_Configuration()
            API_Session = Shodan(Shodan_API_Key)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                try:

                    if self.Type == "Search":
                        Local_Plugin_Name = self.Plugin_Name + "-Search"

                        try:
                            API_Response = API_Session.search(Query)

                        except Exception as e:
                            logging.error(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}.")
                            break

                        JSON_Output_Response = Common.JSON_Handler(API_Response).Dump_JSON()
                        Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                        Current_Step = 0

                        for Shodan_Item in API_Response["matches"]:
                            Shodan_Item_Module = Shodan_Item['_shodan']['module']
                            Shodan_Item_Module = Shodan_Item_Module.replace('-simple-new', '')

                            if Shodan_Item_Module.startswith("http"):
                                Shodan_Item_Host = ""
                                Shodan_Item_Port = 0

                                if 'http' in Shodan_Item:
                                    Shodan_Item_Host = Shodan_Item['http']['host']
                                    Shodan_Item_Response = Shodan_Item['http']['html']

                                elif 'ip_str' in Shodan_Item and 'domains' in Shodan_Item and len(Shodan_Item['domains']) > 0:
                                    Shodan_Item_Host = Shodan_Item['domains'][0]
                                    Shodan_Item_Response = Shodan_Item['data']

                                elif 'ip_str' in Shodan_Item and 'domains' not in Shodan_Item:
                                    Shodan_Item_Host = Shodan_Item['ip_str']
                                    Shodan_Item_Response = Shodan_Item['data']

                                if Shodan_Item_Host:

                                    if 'port' in Shodan_Item_Host:

                                        if int(Shodan_Item['port']) not in [80, 443]:
                                            Shodan_Item_Port = Shodan_Item['port']

                                    if Shodan_Item_Port != 0:
                                        Shodan_Item_URL = f"{Shodan_Item_Module}://{Shodan_Item_Host}:{str(Shodan_Item_Port)}"

                                    else:
                                        Shodan_Item_URL = f"{Shodan_Item_Module}://{Shodan_Item_Host}"

                                    Title = f"Shodan | {str(Shodan_Item_Host)}"

                                    if Shodan_Item_URL not in Cached_Data and Shodan_Item_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Shodan_Item_Response, Shodan_Item_Host, self.The_File_Extensions["Query"])

                                        if Output_file:
                                            Output_Connections.Output([Main_File, Output_file], Shodan_Item_URL, Title, self.Plugin_Name.lower())
                                            Data_to_Cache.append(Shodan_Item_URL)

                                        else:
                                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                        Current_Step += 1

                    elif self.Type == "Host":
                        Local_Plugin_Name = self.Plugin_Name + "-Host"

                        try:
                            API_Response = API_Session.host(Query)

                        except Exception as e:
                            logging.error(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}.")
                            break

                        JSON_Output_Response = Common.JSON_Handler(API_Response).Dump_JSON()
                        Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                        Shodan_URL = f"https://www.{self.Domain}/host/{Query}"
                        Title = f"Shodan | {Query}"

                        if Shodan_URL not in Cached_Data and Shodan_URL not in Data_to_Cache:
                            Shodan_Responses = Common.Request_Handler(Shodan_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                            Shodan_Response = Shodan_Responses["Filtered"]
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Shodan_Response, Query, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Shodan_URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Shodan_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to complete task.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")