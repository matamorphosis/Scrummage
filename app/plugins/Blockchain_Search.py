#!/usr/bin/env python3
# Version 2 - Added Monero Blockchain Support
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type, Limit=10):
        self.Plugin_Name = "Blockchain"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".html"
        self.Abuse_File_Extension = ".json"
        self.Domain = "blockchain.com"
        self.Monero_Domain = "localmonero.co"
        self.Abuse_Domain = "bitcoinabuse.com"
        self.Result_Type = "Blockchain Transaction"
        self.Type = Type
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object="bitcoinabuse", Details_to_Load=["api_key"])

        if Result:
            return Result

        else:
            return None

    def Transaction_Search(self):

        try:
            Local_Plugin_Name = self.Plugin_Name + "-Transaction-Search"
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, Local_Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if self.Type != "Monero":

                    if self.Type in ["BTC", "BCH"]:
                        Query_Regex = Common.Regex_Handler(Query, Custom_Regex=r"[\w]{64}")

                    elif self.Type == "ETH":
                        Query_Regex = Common.Regex_Handler(Query, Custom_Regex=r"(0x[\w]{64})")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid type provided.")

                    if Query_Regex:
                        Main_URL = f"https://www.{self.Domain}/{self.Type}/tx/{Query}"
                        Main_Response = Common.Request_Handler(Main_URL)

                        if self.Type == "BTC":
                            Address_Regex = Common.Regex_Handler(Main_Response, Custom_Regex=r"\/btc\/address\/([\w]{26,34})", Findall=True)

                        elif self.Type == "BCH":
                            Address_Regex = Common.Regex_Handler(Main_Response, Custom_Regex=r"([\w]{42})", Findall=True)

                        elif self.Type == "ETH":
                            Address_Regex = Common.Regex_Handler(Main_Response, Custom_Regex=r"(0x[\w]{40})", Findall=True)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid type provided.")

                        if Address_Regex:
                            Current_Step = 0
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Blockchain Address", self.Task_ID, self.Plugin_Name.lower())

                            for Transaction in Address_Regex:
                                Query_URL = f"https://www.{self.Domain}/{self.Type}/address/{Transaction}"

                                if Query_URL not in Cached_Data and Query_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                    Transaction_Responses = Common.Request_Handler(Query_URL, Filter=True, Host=f"https://www.{self.Domain}")
                                    Transaction_Response = Transaction_Responses["Filtered"]
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Transaction_Response, Transaction, self.The_File_Extension)

                                    if Output_file:
                                        Output_Connections.Output([Output_file], Query_URL, General.Get_Title(Query_URL), self.Plugin_Name.lower())
                                        Data_to_Cache.append(Query_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                    Current_Step += 1

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression.")

                else:
                    Query_URL = f"https://{self.Monero_Domain}/blocks/search/{Query}"
                    Transaction_Response = Common.Request_Handler(Query_URL)

                    if "Whoops, looks like something went wrong." not in Transaction_Response and Query_URL not in Cached_Data and Query_URL not in Data_to_Cache:
                        Transaction_Responses = Common.Request_Handler(Query_URL, Filter=True, Host=f"https://{self.Monero_Domain}")
                        Transaction_Response = Transaction_Responses["Filtered"]
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Transaction_Response, Query, self.The_File_Extension)

                        if Output_file:
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Monero_Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                            Output_Connections.Output([Output_file], Query_URL, General.Get_Title(Query_URL, Requests=True), self.Plugin_Name.lower())
                            Data_to_Cache.append(Query_URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

    def Address_Search(self):

        try:
            Local_Plugin_Name = self.Plugin_Name + "-Address-Search"
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, Local_Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if self.Type == ["BTC", "BCH"]:
                    Query_Regex = Common.Regex_Handler(Query, Custom_Regex=r"([\w]{26,34})")

                elif self.Type == "ETH":
                    Query_Regex = Common.Regex_Handler(Query, Custom_Regex=r"(0x[\w]{40})")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid type provided.")

                if Query_Regex:
                    Main_URL = f"https://www.{self.Domain}/{self.Type}/address/{Query}"
                    Main_Response = Common.Request_Handler(Main_URL)

                    if self.Type == "BTC":
                        Transaction_Regex = Common.Regex_Handler(Main_Response, Custom_Regex=r"\/btc\/tx\/([\w]{64})", Findall=True)

                    elif self.Type == "BCH":
                        Transaction_Regex = Common.Regex_Handler(Main_Response, Custom_Regex=r"([\w]{64})", Findall=True)

                    elif self.Type == "ETH":
                        Transaction_Regex = Common.Regex_Handler(Main_Response, Custom_Regex=r"(0x[\w]{64})", Findall=True)

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid type provided.")

                    if Transaction_Regex:
                        Current_Step = 0
                        Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                        for Transaction in Transaction_Regex:
                            Query_URL = f"https://www.{self.Domain}/{self.Type}/tx/{Transaction}"

                            if Query_URL not in Cached_Data and Query_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                Transaction_Responses = Common.Request_Handler(Query_URL, Filter=True, Host=f"https://www.{self.Domain}")
                                Transaction_Response = Transaction_Responses["Filtered"]
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Transaction_Response, Transaction, self.The_File_Extension)

                                if Output_file:
                                    Output_Connections.Output([Output_file], Query_URL, General.Get_Title(Query_URL), self.Plugin_Name.lower())
                                    Data_to_Cache.append(Query_URL)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                Current_Step += 1

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

    def Address_Abuse_Search(self):

        try:
            Local_Plugin_Name = self.Plugin_Name + "-Address-Abuse-Search"
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            API_Key = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, Local_Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if Common.Regex_Handler(Query, Custom_Regex=r"[\w]{26,34}"):
                    Query_URL = f"https://www.{self.Abuse_Domain}/api/reports/check?address={Query}&api_token={API_Key}"
                    Main_Response = Common.Request_Handler(Query_URL)
                    JSON_Object = Common.JSON_Handler(Main_Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    HTML_URL = f"https://www.bitcoinabuse.com/reports/{Query}"
                    Responses = Common.Request_Handler(HTML_URL, Filter=True, Host=f"https://www.{self.Domain}")
                    Filtered_Response = Responses["Filtered"]
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.Abuse_File_Extension)
                    Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                    if "count" in JSON_Response and JSON_Response["count"] > 0:
                        
                        if HTML_URL not in Cached_Data and HTML_URL not in Data_to_Cache:
                            Title = f"Bitcoin Abuse | {Query}"
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Filtered_Response, Title, self.The_File_Extension)

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], HTML_URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(HTML_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")
        
        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")