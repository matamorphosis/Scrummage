#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type):
        self.Plugin_Name = "Phone"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".html"
        self.Domain = "numberingplans.com"
        self.Result_Type = "Phone Details"
        self.Custom_Headers = {"Origin": "https://www.numberingplans.com"}
        self.Type = Type

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, self.Plugin_Name.lower())
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            def Int_String(Item):

                try:
                    return str(int(Item))

                except:
                    return False

            for Query in self.Query_List:

                if self.Type == "Number":

                    if Common.Regex_Handler(Query, Type="Phone"):
                        Link = f"https://www.{self.Domain}/?page=analysis&sub=phonenr"
                        Data = {"i": Query, "button": "analyse"}
                        Responses = Common.Request_Handler(Link, Method="POST", Application_Form_CT=True, Data=Data, Optional_Headers=self.Custom_Headers, Filter=True, Host=f"https://www.{self.Domain}")
                        Response = Responses["Regular"]
                        Filtered_Response = Responses["Filtered"]

                        if "Number billable as" in Response:
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                            if Query not in Cached_Data and Query not in Data_to_Cache:
                                Title = f"Phone Cellular Number | {Query}"
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Filtered_Response, Title, self.The_File_Extension)
                                
                                if Output_file:
                                    Output_Connections.Output([Output_file], Link, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Link)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Unable to fetch data, your daily limit of requests may have been exceeded.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query in invalid format, please provide query in the international phone number format.") 

                elif self.Type == "IMEI":

                    if Int_String(Query):
                        Link = f"https://www.{self.Domain}/?page=analysis&sub=imeinr"
                        Data = {"i": Query, "button": "analyse"}
                        Responses = Common.Request_Handler(Link, Method="POST", Application_Form_CT=True, Data=Data, Optional_Headers=self.Custom_Headers, Filter=True, Host=f"https://www.{self.Domain}")
                        Response = Responses["Regular"]
                        Filtered_Response = Responses["Filtered"]

                        if "Note:" not in Response:
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                            if Query not in Cached_Data and Query not in Data_to_Cache:
                                Title = f"Phone IMEI Number | {Query}"
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Filtered_Response, Title, self.The_File_Extension)
                                
                                if Output_file:
                                    Output_Connections.Output([Output_file], Link, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Link)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Unable to fetch data, your daily limit of requests may have been exceeded.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query in invalid format, please provide query in integer format.") 

                elif self.Type == "IMSI":

                    if Int_String(Query):
                        Link = f"https://www.{self.Domain}/?page=analysis&sub=imsinr"
                        Data = {"i": Query, "button": "analyse"}
                        Responses = Common.Request_Handler(Link, Method="POST", Application_Form_CT=True, Data=Data, Optional_Headers=self.Custom_Headers, Filter=True, Host=f"https://www.{self.Domain}")
                        Response = Responses["Regular"]
                        Filtered_Response = Responses["Filtered"]

                        if "Note:" not in Response:
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                            if Query not in Cached_Data and Query not in Data_to_Cache:
                                Title = f"Phone IMSI Number | {Query}"
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Filtered_Response, Title, self.The_File_Extension)
                                
                                if Output_file:
                                    Output_Connections.Output([Output_file], Link, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Link)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Unable to fetch data, your daily limit of requests may have been exceeded.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query in invalid format, please provide query in integer format.")

                elif self.Type == "SIM":

                    if Int_String(Query):
                        Link = f"https://www.{self.Domain}/?page=analysis&sub=simnr"
                        Data = {"i": Query, "button": "analyse"}
                        Responses = Common.Request_Handler(Link, Method="POST", Application_Form_CT=True, Data=Data, Optional_Headers=self.Custom_Headers, Filter=True, Host=f"https://www.{self.Domain}")
                        Response = Responses["Regular"]
                        Filtered_Response = Responses["Filtered"]

                        if "Note:" not in Response:
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                            if Query not in Cached_Data and Query not in Data_to_Cache:
                                Title = f"Phone SIM Number | {Query}"
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Filtered_Response, Title, self.The_File_Extension)
                                
                                if Output_file:
                                    Output_Connections.Output([Output_file], Link, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Link)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Unable to fetch data, your daily limit of requests may have been exceeded.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query in invalid format, please provide query in integer format.") 

                elif self.Type == "ISPC":

                    if Int_String(Query):
                        Link = f"https://www.{self.Domain}/?page=analysis&sub=ispcnr"
                        Data = {"i": Query, "button": "analyse"}
                        Responses = Common.Request_Handler(Link, Method="POST", Application_Form_CT=True, Data=Data, Optional_Headers=self.Custom_Headers, Filter=True, Host=f"https://www.{self.Domain}")
                        Response = Responses["Regular"]
                        Filtered_Response = Responses["Filtered"]

                        if "Note:" not in Response:
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                            if Query not in Cached_Data and Query not in Data_to_Cache:
                                Title = f"Phone ISPC Number | {Query}"
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Filtered_Response, Title, self.The_File_Extension)
                                
                                if Output_file:
                                    Output_Connections.Output([Output_file], Link, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Link)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Unable to fetch data, your daily limit of requests may have been exceeded.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query in invalid format, please provide query in integer format.")                    

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")