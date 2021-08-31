#!/usr/bin/env python3
import os, logging, urllib.parse, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type, Limit=10):
        self.Plugin_Name = "NZ Business"
        self.Concat_Plugin_Name = "nzbusiness"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".html"
        self.Domain = "app.companiesoffice.govt.nz"
        self.Result_Type = "Company Details"
        self.Type = Type
        self.Limit = General.Get_Limit(Limit)

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

                    if self.Type == "NZBN":
                        Main_URL = f'https://{self.Domain}/companies/app/ui/pages/companies/search?q={Query}&entityTypes=ALL&entityStatusGroups=ALL&incorpFrom=&incorpTo=&addressTypes=ALL&addressKeyword=&start=0&limit=1&sf=&sd=&advancedPanel=true&mode=advanced#results'
                        Responses = Common.Request_Handler(Main_URL, Filter=True, Host=f"https://{self.Domain}")
                        Response = Responses["Filtered"]

                        try:

                            if 'An error has occurred and the requested action cannot be performed.' not in Response:
                                Query = str(int(Query))

                                if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, f"new-zealand-business-number-{Query.lower()}", self.The_File_Extension)

                                    if Output_file:
                                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name)
                                        Output_Connections.Output([Output_file], Main_URL, f"New Zealand Business Number {Query}", self.Concat_Plugin_Name)
                                        Data_to_Cache.append(Main_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        except:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided for NZBN Search.")

                    elif self.Type == "NZCN":

                        try:
                            URL_Query = urllib.parse.quote(Query)
                            Main_URL = f'https://{self.Domain}/companies/app/ui/pages/companies/search?q={URL_Query}&entityTypes=ALL&entityStatusGroups=ALL&incorpFrom=&incorpTo=&addressTypes=ALL&addressKeyword=&start=0&limit={str(self.Limit)}&sf=&sd=&advancedPanel=true&mode=advanced#results'
                            Responses = Common.Request_Handler(Main_URL, Filter=True, Host=f"https://{self.Domain}")
                            Response = Responses["Filtered"]
                            NZCN_Regex = Common.Regex_Handler(Query, Type="Company_Name")

                            if NZCN_Regex:
                                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Response, Query, self.The_File_Extension)
                                NZBNs_Regex = Common.Regex_Handler(Response, Custom_Regex=r"\<span\sclass\=\"entityName\"\>([\w\d\s\-\_\&\|\!\@\#\$\%\^\*\(\)\.\,]+)\<\/span\>\s<span\sclass\=\"entityInfo\"\>\((\d+)\)\s\(NZBN\:\s(\d+)\)", Findall=True)

                                if NZBNs_Regex:
                                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name)

                                    for NZCN, NZ_ID, NZBN_URL in NZBNs_Regex:
                                        Full_NZBN_URL = f'https://{self.Domain}/companies/app/ui/pages/companies/{NZ_ID}?backurl=H4sIAAAAAAAAAEXLuwrCQBCF4bfZNtHESIpBbLQwhWBeYNgddSF7cWai5O2NGLH7zwenyHgjKWwKGaOfSwjZ3ncPaOt1W9bbsmqaamMoqtepnzIJ7Ltu2RdFHeXIacxf9tEmzgdOAZbuExh0jknk%2F17gRNMrsQMjiqxQmsEHr7Aycp3NfY5PjJbcGSMNoDySCckR%2FPwNLgXMiL4AAAA%3D'

                                        if Full_NZBN_URL not in Cached_Data and Full_NZBN_URL not in Data_to_Cache:
                                            Current_Response = Common.Request_Handler(Full_NZBN_URL)
                                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, str(Current_Response), NZCN.replace(' ', '-'), self.The_File_Extension)

                                            if Output_file:
                                                Output_Connections.Output([Main_File, Output_file], Full_NZBN_URL, f"New Zealand Business Number {NZ_ID} for Query {Query}", self.Concat_Plugin_Name)
                                                Data_to_Cache.append(Full_NZBN_URL)

                                            else:
                                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Response did not match regular expression.")

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query did not match regular expression.")

                        except:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided for NZCN Search.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid request type.")

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to make request.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")