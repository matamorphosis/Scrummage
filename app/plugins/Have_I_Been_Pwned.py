#!/usr/bin/env python3
# Version 2 - Now requires an API key.
import pyhibp, os, logging, plugins.common.General as General, plugins.common.Common as Common
from pyhibp import pwnedpasswords as pw

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type, Limit=10):
        self.Plugin_Name = "Have I Been Pwned"
        self.Concat_Plugin_Name = "haveibeenpwned"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".json"
        self.Domain = "haveibeenpwned.com"
        self.Result_Type_1 = "Account"
        self.Result_Type_2 = "Credentials"
        self.Type = Type
        self.Limit = General.Get_Limit(Limit)

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

            try:
                pyhibp.set_api_key(key=Load_Configuration())

            except:
                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to set API key, make sure it is set in the configuration file.")

            if self.Type == "email":
                Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                Cached_Data_Object = General.Cache(Directory, Local_Plugin_Name)
                Cached_Data = Cached_Data_Object.Get_Cache()

                for Query in self.Query_List:
                    Query_Response = pyhibp.get_pastes(email_address=Query)
                    logging.info(Query_Response)

                    if Query_Response:
                        Current_Domain = Query_Response[0]["Source"]
                        ID = Query_Response[0]["Id"]
                        Link = f"https://www.{Current_Domain}.com/{ID}"
                        JSON_Query_Response = Common.JSON_Handler(Query_Response).Dump_JSON()

                        if Link not in Cached_Data and Link not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, JSON_Query_Response, "email", self.The_File_Extension)

                            if Output_file:
                                Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, self.Result_Type_1, self.Task_ID, Local_Plugin_Name.lower())
                                Output_Connections.Output([Output_file], Link, General.Get_Title(Link), self.Concat_Plugin_Name)
                                Data_to_Cache.append(Link)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                Cached_Data_Object.Write_Cache(Data_to_Cache)

            elif self.Type == "breach":
                Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                Cached_Data_Object = General.Cache(Directory, Local_Plugin_Name)
                Cached_Data = Cached_Data_Object.Get_Cache()

                for Query in self.Query_List:
                    Query_Response = pyhibp.get_single_breach(breach_name=Query)

                    if Query_Response:
                        Current_Domain = Query_Response["Domain"]
                        Link = f"https://www.{Current_Domain}.com/"
                        JSON_Query_Response = Common.JSON_Handler(Query_Response).Dump_JSON()

                        if Link not in Cached_Data and Link not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, JSON_Query_Response, "breach", self.The_File_Extension)

                            if Output_file:
                                Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, self.Result_Type_2, self.Task_ID, Local_Plugin_Name.lower())
                                Output_Connections.Output([Output_file], Link, General.Get_Title(Link), self.Concat_Plugin_Name)
                                Data_to_Cache.append(Link)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                Cached_Data_Object.Write_Cache(Data_to_Cache)

            elif self.Type == "password":
                Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                Cached_Data_Object = General.Cache(Directory, Local_Plugin_Name)
                Cached_Data = Cached_Data_Object.Get_Cache()

                for Query in self.Query_List:
                    Query_Response = pw.is_password_breached(password=Query)
                    logging.info(Query_Response)

                    if Query_Response:
                        Link = f"https://{self.Domain}/Passwords?{Query}"

                        if Link not in Cached_Data and Link not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, str(Query_Response), "password", ".txt")

                            if Output_file:
                                Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, self.Result_Type_2, self.Task_ID, Local_Plugin_Name.lower())
                                Output_Connections.Output([Output_file], Link, General.Get_Title(Link), self.Concat_Plugin_Name)
                                Data_to_Cache.append(Link)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                Cached_Data_Object.Write_Cache(Data_to_Cache)

            elif self.Type == "account":
                Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                Cached_Data_Object = General.Cache(Directory, Local_Plugin_Name)
                Cached_Data = Cached_Data_Object.Get_Cache()

                for Query in self.Query_List:
                    Query_Response = pyhibp.get_account_breaches(account=Query, truncate_response=True)

                    if Query_Response:
                        Current_Step = 0

                        for Response in Query_Response:
                            Current_Response = pyhibp.get_single_breach(breach_name=Response['Name'])
                            JSON_Query_Response = Common.JSON_Handler(Query_Response).Dump_JSON()
                            Link = "https://" + Current_Response['self.Domain']

                            if Current_Response['self.Domain'] not in Cached_Data and Current_Response['self.Domain'] not in Data_to_Cache and Current_Step < int(self.Limit):
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, JSON_Query_Response, "account", self.The_File_Extension)

                                if Output_file:
                                    Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Response['self.Domain'], self.Result_Type_1, self.Task_ID, Local_Plugin_Name.lower())
                                    Output_Connections.Output([Output_file], Link, General.Get_Title(Link), self.Concat_Plugin_Name)
                                    Data_to_Cache.append(Current_Response['self.Domain'])

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                Current_Step += 1

                Cached_Data_Object.Write_Cache(Data_to_Cache)

            else:
                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid Type provided.")

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")