#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Type: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Australian Business"
        self.Concat_Plugin_Name: str = "australianbusiness"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".html", "Query": ".html"}
        self.Domain: str = "abr.business.gov.au"
        self.Result_Type: str = "Company Details"
        self.Limit = General.Get_Limit(Limit)
        self.Type = Type

    def Search(self):

        try:
            Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Concat_Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                try:

                    if self.Type == "ABN":
                        Main_URL = f'https://{self.Domain}/ABN/View?id=' + Query
                        Responses = Common.Request_Handler(url=Main_URL, Filter=True, Host=f"https://www.{self.Domain}")
                        Response = Responses["Regular"]

                        try:

                            if 'Error searching ABN Lookup' not in Response:
                                Query = str(int(Query))
                                Response = Responses["Filtered"]

                                if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, General.Get_Title(Main_URL), self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name)
                                        Output_Connections.Output([Output_file], Main_URL, General.Get_Title(Main_URL).strip(" | ABN Lookup"), self.Concat_Plugin_Name)
                                        Data_to_Cache.append(Main_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - ABN Lookup returned error.")

                        except:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided for ABN Search.")

                    elif self.Type == "ACN":
                        Main_URL = f'https://{self.Domain}/Search/Run'
                        Data = {'SearchParameters.SearchText': Query, 'SearchParameters.AllNames': 'true', 'ctl00%24ContentPagePlaceholder%24SearchBox%24MainSearchButton': 'Search'}
                        Responses = Common.Request_Handler(url=Main_URL, method="POST", Filter=True, Host=f"https://www.{self.Domain}", Data=Data)
                        Response = Responses["Regular"]
                        Filtered_Response = Responses["Filtered"]

                        try:
                            ACN_Regex = Common.Regex_Handler(Query, Type="Company_Name")

                            if ACN_Regex:
                                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Filtered_Response, Query, self.The_File_Extensions["Main"])
                                Current_Step = 0
                                ABNs_Regex = Common.Regex_Handler(Response, Custom_Regex=r"\<input\sid\=\"Results\_NameItems\_\d+\_\_Compressed\"\sname\=\"Results\.NameItems\[\d+\]\.Compressed\"\stype\=\"hidden\"\svalue\=\"(\d{11})\,\d{2}\s\d{3}\s\d{3}\s\d{3}\,0000000001\,Active\,active\,([\d\w\s\&\-\_\.]+)\,Current\,", Findall=True)

                                if ABNs_Regex:
                                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name)

                                    for ABN_URL, ACN in ABNs_Regex:
                                        Full_ABN_URL = f'https://{self.Domain}/ABN/View?abn={ABN_URL}'

                                        if Full_ABN_URL not in Cached_Data and Full_ABN_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                            ACN = ACN.rstrip()
                                            Current_Responses = Common.Request_Handler(url=Full_ABN_URL, Filter=True, Host=f"https://www.{self.Domain}")
                                            Current_Response = Current_Responses["Filtered"]
                                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, str(Current_Response), ACN.replace(' ', '-'), self.The_File_Extensions["Query"])

                                            if Output_file:
                                                Output_Connections.Output([Main_File, Output_file], Full_ABN_URL, General.Get_Title(Full_ABN_URL).strip(" | ABN Lookup"), self.Concat_Plugin_Name)
                                                Data_to_Cache.append(Full_ABN_URL)

                                            else:
                                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                            Current_Step += 1

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Response did not match regular expression.")

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query did not match regular expression.")

                        except:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided for ACN Search.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid request type.")

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to make request.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")