#!/usr/bin/env python3
# Version 2 - Added Monero Blockchain Support
import requests, re, os, logging, plugins.common.General as General

Plugin_Name = "Blockchain"
The_File_Extension = ".html"
Domain = "blockchain.com"
headers = General.URL_Headers(User_Agent=False)

def Transaction_Search(Query_List, Task_ID, Type, **kwargs):

    try:
        Local_Plugin_Name = Plugin_Name + "-Transaction-Search"
        Data_to_Cache = []
        Directory = General.Make_Directory(Plugin_Name.lower())
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        Log_File = General.Logging(Directory, Local_Plugin_Name)
        handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:

            if Type != "monero":

                if Type == "btc" or Type == "bch":
                    Query_Regex = re.search(r"[\d\w]{64}", Query)

                elif Type == "eth":
                    Query_Regex = re.search(r"(0x[\d\w]{64})", Query)

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid type provided.")

                if Query_Regex:
                    Main_URL = f"https://www.{Domain}/{Type}/tx/{Query}"
                    Main_Response = requests.get(Main_URL, headers=headers).text

                    if Type == "btc":
                        Address_Regex = re.findall(r"\/btc\/address\/([\d\w]{26,34})", Main_Response)

                    elif Type == "bch":
                        Address_Regex = re.findall(r"([\d\w]{42})", Main_Response)

                    elif Type == "eth":
                        Address_Regex = re.findall(r"(0x[\w\d]{40})", Main_Response)

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid type provided.")

                    if Address_Regex:
                        Current_Step = 0
                        Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Blockchain Address", Task_ID, Plugin_Name.lower())

                        for Transaction in Address_Regex:
                            Query_URL = f"https://www.{Domain}/{Type}/address/{Transaction}"

                            if Query_URL not in Cached_Data and Query_URL not in Data_to_Cache and Current_Step < int(Limit):
                                Transaction_Response = requests.get(Query_URL, headers=headers).text
                                Transaction_Response = General.Response_Filter(Transaction_Response, f"https://www.{Domain}")
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Transaction_Response, Transaction, The_File_Extension)

                                if Output_file:
                                    Output_Connections.Output([Output_file], Query_URL, General.Get_Title(Query_URL), Plugin_Name.lower())
                                    Data_to_Cache.append(Query_URL)

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                                Current_Step += 1

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

        else:
            Alt_Domain = "localmonero.co"
            Query_URL = f"https://{Alt_Domain}/blocks/search/{Query}"
            Transaction_Response = requests.get(Query_URL, headers=headers).text

            if "Whoops, looks like something went wrong." not in Transaction_Response and Query_URL not in Cached_Data and Query_URL not in Data_to_Cache:
                Transaction_Response = requests.get(Query_URL).text
                Transaction_Response = General.Response_Filter(Transaction_Response, f"https://{Alt_Domain}")
                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Transaction_Response, Query, The_File_Extension)

                if Output_file:
                    Output_Connections = General.Connections(Query, Local_Plugin_Name, Alt_Domain, "Blockchain Transaction", Task_ID, Plugin_Name.lower())
                    Output_Connections.Output([Output_file], Query_URL, General.Get_Title_Requests_Module(Query_URL), Plugin_Name.lower())
                    Data_to_Cache.append(Query_URL)

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

        if Cached_Data:
            General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "a")

        else:
            General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "w")

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")

def Address_Search(Query_List, Task_ID, Type, **kwargs):

    try:
        Local_Plugin_Name = Plugin_Name + "-Address-Search"
        Data_to_Cache = []
        Directory = General.Make_Directory(Plugin_Name.lower())
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        Log_File = General.Logging(Directory, Local_Plugin_Name)
        handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:

            if Type == "btc" or Type == "bch":
                Query_Regex = re.search(r"([\d\w]{26,34})", Query)

            elif Type == "eth":
                Query_Regex = re.search(r"(0x[\w\d]{40})", Query)

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid type provided.")

            if Query_Regex:
                Main_URL = f"https://www.{Domain}/{Type}/address/{Query}"
                Main_Response = requests.get(Main_URL, headers=headers).text

                if Type == "btc":
                    Transaction_Regex = re.findall(r"\/btc\/tx\/([\d\w]{64})", Main_Response)

                elif Type == "bch":
                    Transaction_Regex = re.findall(r"([\d\w]{64})", Main_Response)

                elif Type == "eth":
                    Transaction_Regex = re.findall(r"(0x[\d\w]{64})", Main_Response)

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid type provided.")

                if Transaction_Regex:
                    Current_Step = 0
                    Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Blockchain Transaction", Task_ID, Plugin_Name.lower())

                    for Transaction in Transaction_Regex:
                        Query_URL = f"https://www.{Domain}/{Type}/tx/{Transaction}"

                        if Query_URL not in Cached_Data and Query_URL not in Data_to_Cache and Current_Step < int(Limit):
                            Transaction_Response = requests.get(Query_URL, headers=headers).text
                            Transaction_Response = General.Response_Filter(Transaction_Response, f"https://www.{Domain}")
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Transaction_Response, Transaction, The_File_Extension)

                            if Output_file:
                                Output_Connections.Output([Output_file], Query_URL, General.Get_Title(Query_URL), Plugin_Name.lower())
                                Data_to_Cache.append(Query_URL)

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                            Current_Step += 1

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")