#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, plugins.common.checkdmarc as checkdmarc, os, logging

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Plugin_Name: str = "DNS Reconnaissance"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Concat_Plugin_Name: str = "dnsrecon"
        self.Result_Type: str = "Domain Information"

    def Search(self):

        try:
            Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            try:
                DNS_Info = checkdmarc.check_domains(self.Query_List)

                if len(self.Query_List) > 1:

                    for DNS_Item in DNS_Info:
                        Query = DNS_Item['base_domain']
                        Output_Dict = Common.JSON_Handler(DNS_Item).Dump_JSON()
                        Link: str = f"https://www.{Query}"
                        Title: str = f"DNS Information for {Common.Fang().Defang(DNS_Item['base_domain'])}"

                        if Link not in Data_to_Cache and Link not in Cached_Data:
                            Responses = Common.Request_Handler(url=Link, Filter=True, Host=f"https://www.{Query}")
                            Response = Responses["Filtered"]
                            Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Output_Dict, Query, self.The_File_Extensions["Main"])
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, Title, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections = General.Connections(Query, self.Plugin_Name, Query, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)
                                Output_Connections.Output([Main_File, Output_file], Link, Title, self.Concat_Plugin_Name)
                                Data_to_Cache.append(Link)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                else:
                    Query = DNS_Info['base_domain']
                    Output_Dict = Common.JSON_Handler(Query).Dump_JSON()
                    Link: str = f"https://www.{Query}"
                    Title: str = f"DNS Information for {Common.Fang().Defang(DNS_Item['base_domain'])}"

                    if Link not in Data_to_Cache and Link not in Cached_Data:
                        Responses = Common.Request_Handler(url=Link, Filter=True, Host=f"https://www.{Query}")
                        Response = Responses["Filtered"]
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Output_Dict, Query, self.The_File_Extensions["Main"])
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, Title, self.The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections = General.Connections(Query, self.Plugin_Name, Query, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)
                            Output_Connections.Output([Main_File, Output_file], Link, Title, self.Concat_Plugin_Name)
                            Data_to_Cache.append(Link)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

            except:
                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Error retrieving DNS details.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")