#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common
from pyhunter import PyHunter

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type, Limit=10):
        self.Plugin_Name = "Hunter"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "hunter.io"
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
            Hunter_API_Key = self.Load_Configuration()
            API_Session = PyHunter(Hunter_API_Key)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                try:

                    if self.Type == "Domain":

                        if Common.Regex_Handler(Query, Type="Domain"):
                            Local_Plugin_Name = self.Plugin_Name + "-Domain"
                            API_Response = API_Session.domain_search(Query)
                            JSON_Output_Response = Common.JSON_Handler(API_Response).Dump_JSON()

                            if API_Response.get("domain") and API_Response.get("emails"):
                                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                                Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Account", self.Task_ID, self.Plugin_Name.lower())
                                Current_Step = 0

                                for Hunter_Item in API_Response["emails"]:
                                    Current_Email_Address = Hunter_Item["value"]
                                    Current_Hunter_Item_Host = f"https://{self.Domain}/verify/{Current_Email_Address}"
                                    Current_Hunter_Item_Responses = Common.Request_Handler(Current_Hunter_Item_Host, Filter=True, Host=f"https://{self.Domain}")
                                    Filtered_Response = Current_Hunter_Item_Responses["Filtered"]
                                    Title = "Hunter | " + Current_Email_Address

                                    if Current_Email_Address not in Cached_Data and Current_Email_Address not in Data_to_Cache and Current_Step < int(self.Limit):
                                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Filtered_Response, Current_Hunter_Item_Host, self.The_File_Extensions["Query"])

                                        if Output_file:
                                            Output_Connections.Output([Main_File, Output_file], Current_Hunter_Item_Host, Title, self.Plugin_Name.lower())
                                            Data_to_Cache.append(Current_Email_Address)

                                        else:
                                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                        Current_Step += 1

                    elif self.Type == "Email":

                        if Common.Regex_Handler(Query, Type="Email"):
                            Local_Plugin_Name = self.Plugin_Name + "-Email"
                            API_Response = API_Session.email_verifier(Query)
                            JSON_Output_Response = Common.JSON_Handler(API_Response).Dump_JSON()

                            if API_Response.get("email") and API_Response.get("sources"):
                                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                                Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Account Source", self.Task_ID, self.Plugin_Name.lower())
                                Current_Step = 0

                                for Hunter_Item in API_Response["sources"]:
                                    Current_Hunter_Item_Host = Hunter_Item["uri"]
                                    Current_Hunter_Item_Domain = Hunter_Item["Domain"]

                                    if 'http://' in Current_Hunter_Item_Host:
                                        Current_Hunter_Item_Responses = Common.Request_Handler(Current_Hunter_Item_Host, Filter=True, Host=f"http://{Current_Hunter_Item_Domain}")
                                        Filtered_Response = Current_Hunter_Item_Responses["Filtered"]

                                    elif 'https://' in Current_Hunter_Item_Host:
                                        Current_Hunter_Item_Responses = Common.Request_Handler(Current_Hunter_Item_Host, Filter=True, Host=f"https://{Current_Hunter_Item_Domain}")
                                        Filtered_Response = Current_Hunter_Item_Responses["Filtered"]

                                    else:
                                        Filtered_Response = Common.Request_Handler(Current_Hunter_Item_Host)

                                    Title = "Hunter | " + Current_Hunter_Item_Host

                                    if Current_Hunter_Item_Host not in Cached_Data and Current_Hunter_Item_Host not in Data_to_Cache and Current_Step < int(self.Limit):
                                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Filtered_Response, Current_Hunter_Item_Host, self.The_File_Extensions["Query"])

                                        if Output_file:
                                            Output_Connections.Output([Main_File, Output_file], Current_Hunter_Item_Host, Title, self.Plugin_Name.lower())
                                            Data_to_Cache.append(Current_Hunter_Item_Host)

                                        else:
                                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                        Current_Step += 1

                except Exception as e:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to complete task - {str(e)}")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")