#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Default Password"
        self.Concat_Plugin_Name: str = "defaultpassword"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension: str = ".html"
        self.Domain: str = "default-password.info"
        self.Result_Type: str = "Credentials"
        self.Limit = General.Get_Limit(Limit)

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
                URL_Body = f'https://{self.Domain}'
                Main_URL = URL_Body + '/' + Query.lower().replace(' ', '-')
                Responses = Common.Request_Handler(url=Main_URL, Filter=True, Host=f"https://www.{self.Domain}")
                Response = Responses["Regular"]
                Filtered_Response = Responses["Filtered"]
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Filtered_Response, Query, self.The_File_Extension)
                Regex = Common.Regex_Handler(Response, Custom_Regex=r"\<tr\>\s+\<td\sclass\=\"name\"\>\s+\<a\shref\=\"([\/\d\w\-\+\?\.]+)\"\>([\/\d\w\-\+\?\.\(\)\s\,\;\:\~\`\!\@\#\$\%\^\&\*\[\]\{\}]+)\<\/a\>\s+\<\/td\>", Findall=True)

                if Regex:
                    Current_Step = 0
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)

                    for URL, Title in Regex:
                        Item_URL = URL_Body + URL
                        Current_Response = Common.Request_Handler(url=Item_URL)
                        Current_Item_Regex = Common.Regex_Handler(Current_Response, Custom_Regex=r"\<button\sclass\=\"btn\sbtn\-primary\spassword\"\s+data\-data\=\"([\-\d\w\?\/]+)\"\s+data\-toggle\=\"modal\"\s+data\-target\=\"\#modal\"\s+\>show\sme\!\<\/button\>")
                        
                        if Current_Item_Regex:

                            try:
                                Detailed_Item_URL = URL_Body + Current_Item_Regex.group(1)
                                Detailed_Responses = Common.Request_Handler(url=Detailed_Item_URL, Filter=True, Host=f"https://www.{self.Domain}")
                                Detailed_Response = Detailed_Responses["Regular"]
                                JSON_Response = Common.JSON_Handler(Detailed_Response).Is_JSON()

                                if JSON_Response:
                                    Output_Response: str = "<head><title>" + JSON_Response["title"] + "</title></head>\n"
                                    Output_Response = Output_Response + JSON_Response["data"]

                                else:
                                    Output_Response = Detailed_Responses["Filtered"]

                                if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Output_Response, Title, self.The_File_Extension)

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], Item_URL, General.Get_Title(Item_URL), self.Concat_Plugin_Name)
                                        Data_to_Cache.append(Item_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                    Current_Step += 1

                            except:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to generate output, may have a blank detailed response.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression for current result.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression for provided query.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")