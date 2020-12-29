#!/usr/bin/env python3
import pyhibp, json, os, logging, plugins.common.General as General, plugins.common.Connectors as Connectors
from pyhibp import pwnedpasswords as pw
# Version 2 of this plugin. Now requires an API key.

Plugin_Name = "Have-I-Been-Pwned"
Concat_Plugin_Name = "haveibeenpwned"
The_File_Extension = ".json"
Domain = "haveibeenpwned.com"

def Load_Configuration():
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Connectors.Set_Configuration_File()) as JSON_File:
            Configuration_Data = json.load(JSON_File)
            HIBP_Details = Configuration_Data[Concat_Plugin_Name]
            API_Key = HIBP_Details['api_key']

            if API_Key:
                return API_Key

            else:
                return None

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to load API details.")

def Search(Query_List, Task_ID, Type_of_Query, **kwargs):

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

        try:
            pyhibp.set_api_key(key=Load_Configuration())

        except:
            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to set API key, make sure it is set in the configuration file.")

        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        if Type_of_Query == "email":
            Local_Plugin_Name = Plugin_Name + "-" + Type_of_Query
            Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

            for Query in Query_List:
                Query_Response = pyhibp.get_pastes(email_address=Query)
                logging.info(Query_Response)

                if Query_Response:
                    Current_Domain = Query_Response[0]["Source"]
                    ID = Query_Response[0]["Id"]
                    Link = f"https://www.{Current_Domain}.com/{ID}"
                    JSON_Query_Response = json.dumps(Query_Response, indent=4, sort_keys=True)

                    if Link not in Cached_Data and Link not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, JSON_Query_Response, "email", The_File_Extension)

                        if Output_file:
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Account", Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output([Output_file], Link, General.Get_Title(Link), Concat_Plugin_Name)
                            Data_to_Cache.append(Link)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

            General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

        elif Type_of_Query == "breach":
            Local_Plugin_Name = Plugin_Name + "-" + Type_of_Query
            Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

            for Query in Query_List:
                Query_Response = pyhibp.get_single_breach(breach_name=Query)

                if Query_Response:
                    Current_Domain = Query_Response["Domain"]
                    Link = f"https://www.{Current_Domain}.com/"
                    JSON_Query_Response = json.dumps(Query_Response, indent=4, sort_keys=True)

                    if Link not in Cached_Data and Link not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, JSON_Query_Response, "breach", The_File_Extension)

                        if Output_file:
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Credentials", Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output([Output_file], Link, General.Get_Title(Link), Concat_Plugin_Name)
                            Data_to_Cache.append(Link)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

            General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

        elif Type_of_Query == "password":
            Local_Plugin_Name = Plugin_Name + "-" + Type_of_Query
            Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

            for Query in Query_List:
                Query_Response = pw.is_password_breached(password=Query)
                logging.info(Query_Response)

                if Query_Response:
                    Link = f"https://{Domain}/Passwords?{Query}"

                    if Link not in Cached_Data and Link not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, str(Query_Response), "password", ".txt")

                        if Output_file:
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Credentials", Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output([Output_file], Link, General.Get_Title(Link), Concat_Plugin_Name)
                            Data_to_Cache.append(Link)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

            General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

        elif Type_of_Query == "account":
            Local_Plugin_Name = Plugin_Name + "-" + Type_of_Query
            Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

            for Query in Query_List:
                Query_Response = pyhibp.get_account_breaches(account=Query, truncate_response=True)

                if Query_Response:
                    Current_Step = 0

                    for Response in Query_Response:
                        Current_Response = pyhibp.get_single_breach(breach_name=Response['Name'])
                        JSON_Query_Response = json.dumps(Current_Response, indent=4, sort_keys=True)
                        Link = "https://" + Current_Response['Domain']

                        if Current_Response['Domain'] not in Cached_Data and Current_Response['Domain'] not in Data_to_Cache and Current_Step < int(Limit):
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, JSON_Query_Response, "account", The_File_Extension)

                            if Output_file:
                                Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Response['Domain'], "Account", Task_ID, Local_Plugin_Name.lower())
                                Output_Connections.Output([Output_file], Link, General.Get_Title(Link), Concat_Plugin_Name)
                                Data_to_Cache.append(Current_Response['Domain'])

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                            Current_Step += 1

            General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

        else:
            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid type provided.")

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")