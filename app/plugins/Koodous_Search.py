#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Koodous"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "koodous.com"
        self.Result_Type: str = "Application"
        self.Limit = General.Get_Limit(Limit)

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
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Pagination = 25
                Case: bool = bool()
                Results: list = list()
                Params = {'search': Query}
                URL = f"https://api.{self.Domain}/apks?search={Query}"
                Response = Common.Request_Handler(url=URL, Params=Params)
                JSON_Response = Common.JSON_Handler(Response).To_JSON_Loads()

                if JSON_Response.get("next") and JSON_Response.get("results") and len(JSON_Response["results"]) > 0:

                    if self.Limit <= Pagination:
                        Results = JSON_Response["results"][:self.Limit]

                    else:
                        Tally = Pagination

                        while JSON_Response.get("next"):
                            Next_URL = JSON_Response["next"]
                            Response = Common.Request_Handler(url=Next_URL, Params=Params)
                            JSON_Response = Common.JSON_Handler(Response).To_JSON_Loads()
                            Current_Results = JSON_Response["results"]

                            if Tally < self.Limit:
                                Difference = self.Limit - Tally

                                if Difference >= Pagination:
                                    Results.extend(Current_Results)
                                    Tally += Pagination

                                else:

                                    if Difference <= len(Current_Results):
                                        Results.extend(Current_Results[:Difference])

                                    else:
                                        Results.extend(Current_Results)

                            else:
                                break

                    Case: bool = True

                elif JSON_Response.get("results") and len(JSON_Response["results"]) > 0:
                    Current_Results = JSON_Response["results"]

                    if self.Limit <= len(Current_Results):
                        Results = Current_Results[:self.Limit]

                    else:
                        Results = Current_Results

                    Case: bool = True

                if Case:
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Common.JSON_Handler(Results).Dump_JSON(), Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                    for Result in Results:
                        Result_URL: str = f"https://koodous.com/apks/{Result['sha256']}"
                        
                        if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache:
                            Responses = Common.Request_Handler(url=Result_URL, Filter=True, Host=f"https://{self.Domain}")
                            Response = Responses["Filtered"]

                            if Result.get("displayed_version"):
                                Title = f"{self.Plugin_Name} | {Query} {Result['displayed_version']}"

                            else:
                                Title = f"{self.Plugin_Name} | {Query}"

                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, Title, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Result_URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Result_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")