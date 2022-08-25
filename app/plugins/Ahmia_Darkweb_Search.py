#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Type: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Ahmia"
        self.Tor_Plugin_Name: str = "Ahmia-Tor"
        self.I2P_Plugin_Name: str = "Ahmia-I2P"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension: str = ".html"
        self.Tor_Pull_URL: str = str()
        self.I2P_Pull_URL: str = str()
        self.Domain: str = "ahmia.fi"
        self.Tor_General_URL = f"https://{self.Domain}/search/?q="
        self.I2P_General_URL = f"https://{self.Domain}/search/i2p/?q="
        self.Tor_Scrape_Regex_URL = r"(http\:\/\/[\d\w]+\.onion(?:\/[\/\.\-\?\=\%\d\w]+)?)"
        self.I2P_Scrape_Regex_URL = r"(http\:\/\/[\d\w]+\.i2p(?:\/[\/\.\-\?\=\%\d\w]+)?)"
        self.Result_Type: str = "Darkweb Link"
        self.Limit = General.Get_Limit(Limit)
        self.Type = Type

    def Search(self):

        try:
            Data_to_Cache: list = list()
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

                if self.Type == "Tor":
                    self.Tor_Pull_URL = self.Tor_General_URL + Query
                    Responses = Common.Request_Handler(url=self.Tor_Pull_URL, Filter=True, Host=f"https://{self.Domain}", Scrape_Regex_URL=self.Tor_Scrape_Regex_URL)
                    Tor_Scrape_URLs = Responses["Scraped"]

                    if Tor_Scrape_URLs:
                        Output_file = General.Main_File_Create(Directory, self.Tor_Plugin_Name.lower(), Responses["Filtered"], Query, self.The_File_Extension)

                        if Output_file:
                            Current_Step = 0
                            Output_Connections = General.Connections(Query, self.Tor_Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                            for URL in Tor_Scrape_URLs:

                                if URL not in Cached_Data and URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                    Title = f"Ahmia Tor | {Common.Fang().Defang(URL)}"
                                    Output_Connections.Output([Output_file], URL, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(URL)
                                    Current_Step += 1

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - No Tor links scraped.")


                elif self.Type == "I2P":
                    self.I2P_Pull_URL = self.I2P_General_URL + Query
                    Responses = Common.Request_Handler(url=self.I2P_Pull_URL, Filter=True, Host=f"https://{self.Domain}", Scrape_Regex_URL=self.I2P_Scrape_Regex_URL)
                    I2P_Scrape_URLs = Responses["Scraped"]

                    if I2P_Scrape_URLs:
                        Output_file = General.Main_File_Create(Directory, self.I2P_Plugin_Name.lower(), Responses["Filtered"], Query, self.The_File_Extension)

                        if Output_file:
                            Current_Step = 0
                            Output_Connections = General.Connections(Query, self.I2P_Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                            for URL in I2P_Scrape_URLs:

                                if URL not in Cached_Data and URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                    Title = f"Ahmia I2P | {Common.Fang().Defang(URL)}"
                                    Output_Connections.Output([Output_file], URL, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(URL)
                                    Current_Step += 1

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - No I2P links scraped.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid type provided.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")