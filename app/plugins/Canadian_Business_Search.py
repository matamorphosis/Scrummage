#!/usr/bin/env python3
import os, logging, urllib.parse, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type, Limit=10):
        self.Plugin_Name = "Canadian Business"
        self.Concat_Plugin_Name = "canadianbusiness"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "beta.canadasbusinessregistries.ca"
        self.Result_Type = "Company Details"
        self.Limit = General.Get_Limit(Limit)
        self.Type = Type

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
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                try:

                    if self.Type == "CBN":
                        Main_API_URL = f'https://searchapi.mrasservice.ca/Search/api/v1/search?fq=keyword:%7B{Query}%7D+Status_State:Active&lang=en&queryaction=fieldquery&sortfield=Company_Name&sortorder=asc'
                        Response = Common.Request_Handler(Main_API_URL)
                        JSON_Object = Common.JSON_Handler(Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()
                        Indented_JSON_Response = JSON_Object.Dump_JSON()
                        Main_Output_File = General.Main_File_Create(Directory, self.Plugin_Name, Indented_JSON_Response, Query, self.The_File_Extensions["Main"])

                        try:

                            if JSON_Response['count'] != 0:
                                Query = str(int(Query))
                                Main_URL = f'https://{self.Domain}/search/results?search=%7B{Query}%7D&status=Active'
                                Responses = Common.Request_Handler(Main_URL, Filter=True, Host=f"https://{self.Domain}")
                                Response = Responses["Filtered"]

                                if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, General.Get_Title(Main_URL), self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain.strip("beta."), self.Result_Type, self.Task_ID, self.Plugin_Name)
                                        Output_Connections.Output([Main_Output_File, Output_file], Main_URL, f"Canadian Business Number {Query}", self.Concat_Plugin_Name)
                                        Data_to_Cache.append(Main_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        except:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided for CBN Search.")

                    elif self.Type == "CCN":
                        Total_Results = 0
                        Iterator = "page=0"

                        while (self.Limit > Total_Results) and Iterator is not None:
                            Main_URL = 'https://searchapi.mrasservice.ca/Search/api/v1/search?fq=keyword:%7B' + urllib.parse.quote(Query) + f'%7D+Status_State:Active&lang=en&queryaction=fieldquery&sortfield=Company_Name&sortorder=asc&{Iterator}'
                            Response = Common.Request_Handler(Main_URL)
                            JSON_Object = Common.JSON_Handler(Response)
                            JSON_Response = JSON_Object.To_JSON_Loads()
                            Total_Results += len(JSON_Response["docs"])

                            if "paging" in JSON_Response and "next" in JSON_Response.get("paging"):
                                Iterator = JSON_Response["paging"]["next"]

                            else:
                                Iterator = None

                            Indented_JSON_Response = JSON_Object.Dump_JSON()

                            try:
                                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Indented_JSON_Response, Query, self.The_File_Extensions["Main"])
                                Current_Step = 0
                                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain.strip("beta."), self.Result_Type, self.Task_ID, self.Plugin_Name)

                                for JSON_Item in JSON_Response['docs']:

                                    if JSON_Item.get('BN'):
                                        CCN = JSON_Item['Company_Name']
                                        CBN = str(int(JSON_Item['BN']))

                                        Full_CCN_URL = f'https://{self.Domain}/search/results?search=%7B{CBN}%7D&status=Active'

                                        if Full_CCN_URL not in Cached_Data and Full_CCN_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                            Current_Responses = Common.Request_Handler(Full_CCN_URL, Filter=True, Host=f"https://{self.Domain}")
                                            Current_Response = Current_Responses["Filtered"]
                                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, str(Current_Response), CCN.replace(' ', '-'), self.The_File_Extensions["Query"])

                                            if Output_file:
                                                Output_Connections.Output([Main_File, Output_file], Full_CCN_URL, f"Canadian Business Number {CBN} for Query {Query}", self.Concat_Plugin_Name)
                                                Data_to_Cache.append(Full_CCN_URL)

                                            else:
                                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                            Current_Step += 1

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Unable to retrieve business numbers from the JSON response.")

                            except:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided for CCN Search.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid request type.")

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to make request.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")