#!/usr/bin/env python3
import os, re, logging, urllib.parse, plugins.common.General as General

Plugin_Name = "NZ-Business"
Concat_Plugin_Name = "nzbusiness"
The_File_Extension = ".html"
Domain = "app.companiesoffice.govt.nz"

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

                if Type == "NZBN":
                    Main_URL = f'https://{Domain}/companies/app/ui/pages/companies/search?q={Query}&entityTypes=ALL&entityStatusGroups=ALL&incorpFrom=&incorpTo=&addressTypes=ALL&addressKeyword=&start=0&limit=1&sf=&sd=&advancedPanel=true&mode=advanced#results'
                    Responses = General.Request_Handler(Main_URL, Filter=True, Host=f"https://{Domain}")
                    Response = Responses["Filtered"]

                    try:

                        if 'An error has occurred and the requested action cannot be performed.' not in Response:
                            Query = str(int(Query))

                            if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, f"new-zealand-business-number-{Query.lower()}", The_File_Extension)

                                if Output_file:
                                    Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Company Details", Task_ID, Plugin_Name)
                                    Output_Connections.Output([Output_file], Main_URL, f"New Zealand Business Number {Query}", Concat_Plugin_Name)
                                    Data_to_Cache.append(Main_URL)

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                    except:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid query provided for NZBN Search.")

                elif Type == "NZCN":

                    try:
                        Limit = General.Get_Limit(kwargs)
                        URL_Query = urllib.parse.quote(Query)
                        Main_URL = f'https://{Domain}/companies/app/ui/pages/companies/search?q={URL_Query}&entityTypes=ALL&entityStatusGroups=ALL&incorpFrom=&incorpTo=&addressTypes=ALL&addressKeyword=&start=0&limit={str(Limit)}&sf=&sd=&advancedPanel=true&mode=advanced#results'
                        Responses = General.Request_Handler(Main_URL, Filter=True, Host=f"https://{Domain}")
                        Response = Responses["Filtered"]
                        NZCN_Regex = re.search(r".*[a-zA-Z].*", Query)

                        if NZCN_Regex:
                            Main_File = General.Main_File_Create(Directory, Plugin_Name, Response, Query, The_File_Extension)
                            NZBNs_Regex = re.findall(r"\<span\sclass\=\"entityName\"\>([\w\d\s\-\_\&\|\!\@\#\$\%\^\*\(\)\.\,]+)\<\/span\>\s<span\sclass\=\"entityInfo\"\>\((\d+)\)\s\(NZBN\:\s(\d+)\)", Response)

                            if NZBNs_Regex:
                                Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Company Details", Task_ID, Plugin_Name)

                                for NZCN, NZ_ID, NZBN_URL in NZBNs_Regex:
                                    Full_NZBN_URL = f'https://{Domain}/companies/app/ui/pages/companies/{NZ_ID}?backurl=H4sIAAAAAAAAAEXLuwrCQBCF4bfZNtHESIpBbLQwhWBeYNgddSF7cWai5O2NGLH7zwenyHgjKWwKGaOfSwjZ3ncPaOt1W9bbsmqaamMoqtepnzIJ7Ltu2RdFHeXIacxf9tEmzgdOAZbuExh0jknk%2F17gRNMrsQMjiqxQmsEHr7Aycp3NfY5PjJbcGSMNoDySCckR%2FPwNLgXMiL4AAAA%3D'

                                    if Full_NZBN_URL not in Cached_Data and Full_NZBN_URL not in Data_to_Cache:
                                        Current_Response = General.Request_Handler(Full_NZBN_URL)
                                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, str(Current_Response), NZCN.replace(' ', '-'), The_File_Extension)

                                        if Output_file:
                                            Output_Connections.Output([Main_File, Output_file], Full_NZBN_URL, f"New Zealand Business Number {NZ_ID} for Query {Query}", Concat_Plugin_Name)
                                            Data_to_Cache.append(Full_NZBN_URL)

                                        else:
                                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Response did not match regular expression.")

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Query did not match regular expression.")

                    except:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid query provided for NZCN Search.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid request type.")

            except:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to make request.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")