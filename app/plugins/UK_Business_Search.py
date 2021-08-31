#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type, Limit=10):
        self.Plugin_Name = "UK Business"
        self.Concat_Plugin_Name = "ukbusiness"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "companieshouse.gov.uk"
        self.Result_Type = "Company Details"
        self.Type = Type
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Concat_Plugin_Name, Details_to_Load=["api_key"])

        if Result:
            return General.Encoder(Result)

        else:
            return None

    def Search(self):

        try:
            Data_to_Cache = []
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

                    if self.Type == "UKBN":
                        Authorization_Key = self.Load_Configuration()

                        if Authorization_Key:
                            Authorization_Key = "Basic " + Authorization_Key
                            headers_auth = {"Authorization": Authorization_Key}
                            Main_URL = f'https://api.{self.Domain}/company/{Query}'
                            Response = Common.Request_Handler(Main_URL, Optional_Headers=headers_auth)
                            JSON_Object = Common.JSON_Handler(Response)
                            JSON_Response = JSON_Object.To_JSON_Loads()
                            Indented_JSON_Response = JSON_Object.Dump_JSON()

                            try:
                                Query = str(int(Query))

                                if Response and '{"errors":[{"error":"company-profile-not-found","self.Type":"ch:service"}]}' not in Response:

                                    if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                                        Current_Company_Number = str(JSON_Response["company_number"])
                                        Result_URL = f'https://beta.{self.Domain}/company/{Current_Company_Number}'
                                        Result_Responses = Common.Request_Handler(Result_URL, Filter=True, Host=f"https://beta.{self.Domain}")
                                        Result_Response = Result_Responses["Filtered"]
                                        UKCN = str(JSON_Response["company_name"])
                                        Main_Output_File = General.Main_File_Create(Directory, self.Plugin_Name, Indented_JSON_Response, Query, self.The_File_Extensions["Main"])
                                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Result_Response, UKCN, self.The_File_Extensions["Query"])

                                        if Output_file:
                                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name)
                                            Output_Connections.Output([Main_Output_File, Output_file], Result_URL, f"UK Business Number {Query}", self.Concat_Plugin_Name)
                                            Data_to_Cache.append(Main_URL)

                                        else:
                                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            except:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided for UKBN Search.")

                        else:
                            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to retrieve API key.")

                    elif self.Type == "UKCN":
                        Authorization_Key = self.Load_Configuration()

                        if Authorization_Key:
                            Authorization_Key = "Basic " + Authorization_Key.decode('ascii')

                            try:
                                Main_URL = f'https://api.{self.Domain}/search/companies?q={Query}&items_per_page={self.Limit}'
                                headers_auth = {"Authorization": Authorization_Key}
                                Response = Common.Request_Handler(Main_URL, Optional_Headers=headers_auth)
                                JSON_Object = Common.JSON_Handler(Response)
                                JSON_Response = JSON_Object.To_JSON_Loads()
                                Indented_JSON_Response = JSON_Object.Dump_JSON()

                                try:

                                    if JSON_Response['total_results'] > 0:
                                        Main_Output_File = General.Main_File_Create(Directory, self.Plugin_Name, Indented_JSON_Response, Query, self.The_File_Extensions["Main"])
                                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name)

                                        for Item in JSON_Response['items']:
                                            UKBN_URL = Item['links']['self']
                                            Full_UKBN_URL = f'https://beta.{self.Domain}{str(UKBN_URL)}'
                                            UKBN = UKBN_URL.strip("/company/")

                                            if Full_UKBN_URL not in Cached_Data and Full_UKBN_URL not in Data_to_Cache:
                                                UKCN = Item['title']
                                                Current_Responses = Common.Request_Handler(Full_UKBN_URL, Filter=True, Host=f"https://beta.{self.Domain}")
                                                Current_Response = Current_Responses["Filtered"]
                                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, str(Current_Response), UKCN, self.The_File_Extensions["Query"])

                                                if Output_file:
                                                    Output_Connections.Output([Main_Output_File, Output_file], Full_UKBN_URL, f"UK Business Number {UKBN} for Query {Query}", self.Concat_Plugin_Name)
                                                    Data_to_Cache.append(Full_UKBN_URL)

                                                else:
                                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                                except:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Error during UKCN Search, perhaps the rate limit has been exceeded.")

                            except:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided for UKCN Search.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to retrieve API key.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid request self.Type.")

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to make request.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")