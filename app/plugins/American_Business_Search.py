#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Type: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "American Business"
        self.Concat_Plugin_Name: str = "americanbusiness"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".html", "Query": ".html"}
        self.Domain: str = "sec.gov"
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

                    if self.Type == "CIK":
                        Main_URL = f'https://www.{self.Domain}/cgi-bin/browse-edgar?action=getcompany&CIK={Query}&owner=exclude&count=40&hidefilings=0'
                        Responses = Common.Request_Handler(url=Main_URL, Filter=True, Host=f"https://www.{self.Domain}")
                        Response = Responses["Regular"]

                        try:

                            if 'No matching CIK.' not in Response:
                                Query = str(int(Query))
                                Response = Responses["Filtered"]

                                if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, f"edgar-american-business-search-{Query.lower()}", self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name)
                                        Output_Connections.Output([Output_file], Main_URL, f"American Business Number (EDGAR) {Query}", self.Concat_Plugin_Name)
                                        Data_to_Cache.append(Main_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                        except:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided for CIK Search.")

                    elif self.Type == "ACN":
                        Main_URL = f'https://www.{self.Domain}/cgi-bin/browse-edgar?company={Query}&owner=exclude&action=getcompany'
                        Responses = Common.Request_Handler(url=Main_URL, Filter=True, Host=f"https://www.{self.Domain}")
                        Response = Responses["Regular"]
                        Filtered_Response = Responses["Filtered"]

                        try:
                            ACN = Common.Regex_Handler(Query, Type="Company_Name")

                            if ACN:
                                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Filtered_Response, Query, self.The_File_Extensions["Main"])
                                Current_Step = 0
                                CIKs_Regex = Common.Regex_Handler(Response, Custom_Regex=r"(\d{10})\<\/a\>\<\/td\>\s+\<td\sscope\=\"row\"\>(.*\S.*)\<\/td\>", Findall=True)

                                if CIKs_Regex:
                                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name)

                                    for CIK_URL, ACN in CIKs_Regex:
                                        Full_CIK_URL = f'https://www.{self.Domain}/cgi-bin/browse-edgar?action=getcompany&CIK={CIK_URL}&owner=exclude&count=40&hidefilings=0'

                                        if Full_CIK_URL not in Cached_Data and Full_CIK_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                            Current_Responses = Common.Request_Handler(url=Full_CIK_URL, Filter=True, Host=f"https://www.{self.Domain}")
                                            Current_Response = Current_Responses["Filtered"]
                                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, str(Current_Response), ACN.replace(' ', '-'), self.The_File_Extensions["Query"])

                                            if Output_file:
                                                Output_Connections.Output([Main_File, Output_file], Full_CIK_URL, f"American Business Number (EDGAR) {CIK_URL} for Query {Query}", self.Concat_Plugin_Name)
                                                Data_to_Cache.append(Full_CIK_URL)

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