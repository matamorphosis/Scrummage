#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Type: str = str()):
        self.Plugin_Name: str = "NameAPI"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "nameapi.org"
        self.Result_Type: str = "Account"
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
            Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, self.Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG) 
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            API_Key = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if self.Type == "Gender":
                    URL = f"http://rc50-api.{self.Domain}/rest/v5.0/genderizer/persongenderizer?apiKey={API_Key}"
                    Data = {"inputPerson":{"type":"NaturalInputPerson","personName":{"nameFields":[{"string":Query,"fieldType":"FULLNAME"}]}}}
                    Response = Common.Request_Handler(url=URL, method="POST", JSON_Data=Data)
                    JSON_Object = Common.JSON_Handler(Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    Output_URL = f"https://www.{self.Domain}/en/demos/name-parser?q={Query}"
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                    if "gender" in JSON_Response and Output_URL not in Cached_Data and Output_URL not in Data_to_Cache:
                        HTML_Output_File_Data = General.JSONDict_to_HTML([JSON_Response], JSON_Output_Response, f"{self.Plugin_Name} Query {Query}")
                        Title = f"{self.Plugin_Name} | {Query}"
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, HTML_Output_File_Data, Title, self.The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Output_URL, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(Output_URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                elif self.Type == "Name":

                    if Common.Regex_Handler(Query, Type="Email"):
                        Search_Query = Query.replace("@", "%40")
                        URL = f"http://rc50-api.{self.Domain}/rest/v5.0/email/emailnameparser?apiKey={API_Key}&emailAddress={Search_Query}"
                        Response = Common.Request_Handler(url=URL)
                        JSON_Object = Common.JSON_Handler(Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()
                        JSON_Output_Response = JSON_Object.Dump_JSON()
                        Output_URL = f"https://www.{self.Domain}/en/demos/name-parser?q={Query}"
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                        if "resultType" in JSON_Response and Output_URL not in Cached_Data and Output_URL not in Data_to_Cache:
                            HTML_Output_File_Data = General.JSONDict_to_HTML([JSON_Response], JSON_Output_Response, f"{self.Plugin_Name} Query {Query}")
                            Title = f"{self.Plugin_Name} | {Query}"
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, HTML_Output_File_Data, Title, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Output_URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Output_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

                elif self.Type == "Disposable":

                    if Common.Regex_Handler(Query, Type="Email"):
                        Search_Query = Query.replace("@", "%40")
                        URL = f"http://rc50-api.{self.Domain}/rest/v5.0/email/disposableemailaddressdetector?apiKey={API_Key}&emailAddress={Search_Query}"
                        Response = Common.Request_Handler(url=URL)
                        JSON_Object = Common.JSON_Handler(Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()
                        JSON_Output_Response = JSON_Object.Dump_JSON()
                        Output_URL = f"https://www.{self.Domain}/en/demos/name-parser?q={Query}"
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                        if "disposable" in JSON_Response and Output_URL not in Cached_Data and Output_URL not in Data_to_Cache:
                            HTML_Output_File_Data = General.JSONDict_to_HTML([JSON_Response], JSON_Output_Response, f"{self.Plugin_Name} Query {Query}")
                            Title = f"{self.Plugin_Name} | {Query}"
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, HTML_Output_File_Data, Title, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Output_URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Output_URL)

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