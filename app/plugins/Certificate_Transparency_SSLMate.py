#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Plugin_Name: str = "SSLMate"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension: str = ".json"
        self.Domain: str = "sslmate.com"
        self.Result_Type: str = "Certificate Details"

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["search_subdomain"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:
            Data_to_Cache: list = list()
            Subdomains = self.Load_Configuration()
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if Subdomains:
                    Request = f'https://api.certspotter.com/v1/issuances?self.Domain={Query}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert'

                else:
                    Request = f'https://api.certspotter.com/v1/issuances?self.Domain={Query}&expand=dns_names&expand=issuer&expand=cert'

                Response = Common.Request_Handler(url=Request)
                JSON_Object = Common.JSON_Handler(Response)
                JSON_Response = JSON_Object.To_JSON_Loads()
                Indented_JSON_Response = JSON_Object.Dump_JSON()

                if 'exists' not in JSON_Response:

                    if JSON_Response:

                        if Request not in Cached_Data and Request not in Data_to_Cache:

                            try:
                                SSLMate_Regex = Common.Regex_Handler(Query, Type="Domain")

                                if SSLMate_Regex:
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name.lower(), Indented_JSON_Response, SSLMate_Regex.group(1), self.The_File_Extension)

                                    if Output_file:
                                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                                        Data_to_Cache.append(Request)

                                        if Subdomains:
                                            Output_Connections.Output([Output_file], Request, f"Subdomain Certificate Search for {Query}", self.Plugin_Name.lower())

                                        else:
                                            Output_Connections.Output([Output_file], Request, f"self.Domain Certificate Search for {Query}", self.Plugin_Name.lower())

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression.")

                            except:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create file.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No response.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query does not exist.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")