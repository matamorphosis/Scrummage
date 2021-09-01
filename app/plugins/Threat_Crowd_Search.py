#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type):
        self.Plugin_Name = "Threat Crowd"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "threatcrowd.org"
        self.Type = Type

    def Search(self):

        try:
            Data_to_Cache = []
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

                if self.Type == "Email":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                        URL = f"https://www.{self.Domain}/searchApi/v2/email/report/?email={Query}"
                        Response = Common.Request_Handler(URL)
                        Search_Response = Common.Request_Handler(URL)
                        JSON_Object = Common.JSON_Handler(Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()

                        if int(JSON_Response.get("response_code")) != 0:
                            JSON_Output_Response = JSON_Object.Dump_JSON()
                            Permalink = JSON_Response.get("permalink")
                            Permalink_Responses = Common.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                            Permalink_Response = Permalink_Responses["Filtered"]
                            Title = f"{self.Plugin_Name} | " + General.Get_Title(Permalink, Requests=True).replace(" | Threatcrowd.org Open Source Threat Intelligence", "")
                            Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Permalink_Response, Query, self.The_File_Extensions["Query"])
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Account", self.Task_ID, Local_Plugin_Name.lower())

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Permalink, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Provided query returned no results.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match query to email regular expression.")

                elif self.Type == "Domain":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                        URL = f"https://www.{self.Domain}/searchApi/v2/self.Domain/report/?self.Domain={Query}"
                        Response = Common.Request_Handler(URL)
                        JSON_Object = Common.JSON_Handler(Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()

                        if int(JSON_Response.get("response_code")) != 0:
                            JSON_Output_Response = JSON_Object.Dump_JSON()
                            Permalink = JSON_Response.get("permalink")
                            Permalink_Responses = Common.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                            Permalink_Response = Permalink_Responses["Filtered"]
                            Title = f"{self.Plugin_Name} | " + General.Get_Title(Permalink, Requests=True).replace(" | Threatcrowd.org Open Source Threat Intelligence", "")
                            Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Permalink_Response, Query, self.The_File_Extensions["Query"])
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Domain Information", self.Task_ID, Local_Plugin_Name.lower())
                            
                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Permalink, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Provided query returned no results.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match query to self.Domain regular expression.")

                elif self.Type == "IP Address":

                    if Common.Regex_Handler(Query, Type="IP"):
                        Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                        URL = f"https://www.{self.Domain}/searchApi/v2/ip/report/?ip={Query}"
                        Response = Common.Request_Handler(URL)
                        JSON_Object = Common.JSON_Handler(Response)
                        JSON_Response = JSON_Object.To_JSON_Loads()

                        if int(JSON_Response.get("response_code")) != 0:
                            JSON_Output_Response = JSON_Object.Dump_JSON()
                            Permalink = JSON_Response.get("permalink")
                            Permalink_Responses = Common.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                            Permalink_Response = Permalink_Responses["Filtered"]
                            Title = f"{self.Plugin_Name} | " + General.Get_Title(Permalink, Requests=True).replace(" | Threatcrowd.org Open Source Threat Intelligence", "")
                            Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Permalink_Response, Query, self.The_File_Extensions["Query"])
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Domain Information", self.Task_ID, Local_Plugin_Name.lower())
                            
                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Permalink, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Provided query returned no results.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match query to IP address regular expression.")

                elif self.Type == "AV":
                    Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                    URL = f"https://www.{self.Domain}/searchApi/v2/antivirus/report/?antivirus={Query}"
                    Response = Common.Request_Handler(URL)
                    JSON_Object = Common.JSON_Handler(Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()

                    if int(JSON_Response.get("response_code")) != 0:
                        JSON_Output_Response = JSON_Object.Dump_JSON()
                        Permalink = JSON_Response.get("permalink")
                        Permalink_Responses = Common.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                        Permalink_Response = Permalink_Responses["Filtered"]
                        Title = f"{self.Plugin_Name} | " + General.Get_Title(Permalink, Requests=True).replace(" | Threatcrowd.org Open Source Threat Intelligence", "")
                        Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Permalink_Response, Query, self.The_File_Extensions["Query"])
                        Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Virus", self.Task_ID, Local_Plugin_Name.lower())
                        
                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Permalink, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Provided query returned no results.")

                elif self.Type == "Virus Report":
                    Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                    URL = f"https://www.{self.Domain}/searchApi/v2/file/report/?resource={Query}"
                    Response = Common.Request_Handler(URL)
                    JSON_Object = Common.JSON_Handler(Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()

                    if int(JSON_Response.get("response_code")) != 0:
                        JSON_Output_Response = JSON_Object.Dump_JSON()
                        Permalink = JSON_Response.get("permalink")
                        Permalink_Responses = Common.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                        Permalink_Response = Permalink_Responses["Filtered"]
                        Title = f"{self.Plugin_Name} | " + General.Get_Title(Permalink, Requests=True).replace(" | Threatcrowd.org Open Source Threat Intelligence", "")
                        Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Permalink_Response, Query, self.The_File_Extensions["Query"])
                        Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Virus Report", self.Task_ID, Local_Plugin_Name.lower())
                        
                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Permalink, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Provided query returned no results.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid Type provided.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")