#!/usr/bin/env python3
import os, re, logging, requests, plugins.common.General as General

Plugin_Name = "American-Business"
Concat_Plugin_Name = "americanbusiness"
The_File_Extensions = {"Main": ".html", "Query": ".html"}
Domain = "sec.gov"
headers = General.URL_Headers(User_Agent=False)

def Search(Query_List, Task_ID, Type, **kwargs):

    try:
        Data_to_Cache = []
        Directory = General.Make_Directory(Concat_Plugin_Name)
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        Log_File = General.Logging(Directory, Concat_Plugin_Name)
        handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)

        for Query in Query_List:

            try:

                if Type == "CIK":
                    Main_URL = f'https://www.{Domain}/cgi-bin/browse-edgar?action=getcompany&CIK={Query}&owner=exclude&count=40&hidefilings=0'
                    Response = requests.get(Main_URL, headers=headers).text

                    try:

                        if 'No matching CIK.' not in Response:
                            Query = str(int(Query))
                            Response = General.Response_Filter(Response, f"https://www.{Domain}")

                            if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, f"edgar-american-business-search-{Query.lower()}", The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Company Details", Task_ID, Plugin_Name)
                                    Output_Connections.Output([Output_file], Main_URL, f"American Business Number (EDGAR) {Query}", Concat_Plugin_Name)
                                    Data_to_Cache.append(Main_URL)

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                    except:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid query provided for CIK Search.")

                elif Type == "ACN":
                    Main_URL = f'https://www.{Domain}/cgi-bin/browse-edgar?company={Query}&owner=exclude&action=getcompany'
                    Response = requests.get(Main_URL, headers=headers).text
                    Filtered_Response = General.Response_Filter(Response, f"https://www.{Domain}")
                    Limit = General.Get_Limit(kwargs)

                    try:
                        ACN = re.search(r".*[a-zA-Z].*", Query)

                        if ACN:
                            Main_File = General.Main_File_Create(Directory, Plugin_Name, Filtered_Response, Query, The_File_Extensions["Main"])
                            Current_Step = 0
                            CIKs_Regex = re.findall(r"(\d{10})\<\/a\>\<\/td\>\s+\<td\sscope\=\"row\"\>(.*\S.*)\<\/td\>", Response)

                            if CIKs_Regex:
                                Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Company Details", Task_ID, Plugin_Name)

                                for CIK_URL, ACN in CIKs_Regex:
                                    Full_CIK_URL = f'https://www.{Domain}/cgi-bin/browse-edgar?action=getcompany&CIK={CIK_URL}&owner=exclude&count=40&hidefilings=0'

                                    if Full_CIK_URL not in Cached_Data and Full_CIK_URL not in Data_to_Cache and Current_Step < int(Limit):
                                        Current_Response = requests.get(Full_CIK_URL, headers=headers).text
                                        Current_Response = General.Response_Filter(Current_Response, f"https://www.{Domain}")
                                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, str(Current_Response), ACN.replace(' ', '-'), The_File_Extensions["Query"])

                                        if Output_file:
                                            Output_Connections.Output([Main_File, Output_file], Full_CIK_URL, f"American Business Number (EDGAR) {CIK_URL} for Query {Query}", Concat_Plugin_Name)
                                            Data_to_Cache.append(Full_CIK_URL)

                                        else:
                                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                                        Current_Step += 1

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Response did not match regular expression.")

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Query did not match regular expression.")

                    except:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid query provided for ACN Search.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid request type.")

            except:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to make request.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")