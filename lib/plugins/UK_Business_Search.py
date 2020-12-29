#!/usr/bin/env python3
import os, json, logging, base64, plugins.common.General as General, plugins.common.Connectors as Connectors

Plugin_Name = "UK-Business"
Concat_Plugin_Name = "ukbusiness"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "companieshouse.gov.uk"

def Load_Configuration():
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Connectors.Set_Configuration_File()) as JSON_File:
            Configuration_Data = json.load(JSON_File)
            API_Details = Configuration_Data[Concat_Plugin_Name]
            API_Key = API_Details['api_key']

            if API_Key:
                API_Key = base64.b64encode(API_Key.encode('ascii'))
                return API_Key

            else:
                return None

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to load location details.")


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

                if Type == "UKBN":
                    Authorization_Key = Load_Configuration()

                    if Authorization_Key:
                        Authorization_Key = "Basic " + Authorization_Key.decode('ascii')
                        headers_auth = {"Authorization": Authorization_Key}
                        Main_URL = f'https://api.{Domain}/company/{Query}'
                        Response = General.Request_Handler(Main_URL, Optional_Headers=headers_auth)
                        JSON_Response = json.loads(Response)
                        Indented_JSON_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)

                        try:
                            Query = str(int(Query))

                            if Response and '{"errors":[{"error":"company-profile-not-found","type":"ch:service"}]}' not in Response:

                                if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                                    Current_Company_Number = str(JSON_Response["company_number"])
                                    Result_URL = f'https://beta.{Domain}/company/{Current_Company_Number}'
                                    Result_Responses = General.Request_Handler(Result_URL, Filter=True, Host=f"https://beta.{Domain}")
                                    Result_Response = Result_Responses["Filtered"]
                                    UKCN = str(JSON_Response["company_name"])
                                    Main_Output_File = General.Main_File_Create(Directory, Plugin_Name, Indented_JSON_Response, Query, The_File_Extensions["Main"])
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Result_Response, UKCN, The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Company Details", Task_ID, Plugin_Name)
                                        Output_Connections.Output([Main_Output_File, Output_file], Result_URL, f"UK Business Number {Query}", Concat_Plugin_Name)
                                        Data_to_Cache.append(Main_URL)

                                    else:
                                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        except:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid query provided for UKBN Search.")

                    else:
                        logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to retrieve API key.")

                elif Type == "UKCN":
                    Authorization_Key = Load_Configuration()

                    if Authorization_Key:
                        Authorization_Key = "Basic " + Authorization_Key.decode('ascii')
                        Limit = General.Get_Limit(kwargs)

                        try:
                            Main_URL = f'https://api.{Domain}/search/companies?q={Query}&items_per_page={Limit}'
                            headers_auth = {"Authorization": Authorization_Key}
                            Response = General.Request_Handler(Main_URL, Optional_Headers=headers_auth)
                            JSON_Response = json.loads(Response)
                            Indented_JSON_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)

                            try:

                                if JSON_Response['total_results'] > 0:
                                    Main_Output_File = General.Main_File_Create(Directory, Plugin_Name, Indented_JSON_Response, Query, The_File_Extensions["Main"])
                                    Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Company Details", Task_ID, Plugin_Name)

                                    for Item in JSON_Response['items']:
                                        UKBN_URL = Item['links']['self']
                                        Full_UKBN_URL = f'https://beta.{Domain}{str(UKBN_URL)}'
                                        UKBN = UKBN_URL.strip("/company/")

                                        if Full_UKBN_URL not in Cached_Data and Full_UKBN_URL not in Data_to_Cache:
                                            UKCN = Item['title']
                                            Current_Responses = General.Request_Handler(Full_UKBN_URL, Filter=True, Host=f"https://beta.{Domain}")
                                            Current_Response = Current_Responses["Filtered"]
                                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, str(Current_Response), UKCN, The_File_Extensions["Query"])

                                            if Output_file:
                                                Output_Connections.Output([Main_Output_File, Output_file], Full_UKBN_URL, f"UK Business Number {UKBN} for Query {Query}", Concat_Plugin_Name)
                                                Data_to_Cache.append(Full_UKBN_URL)

                                            else:
                                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                            except:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Error during UKCN Search, perhaps the rate limit has been exceeded.")

                        except:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid query provided for UKCN Search.")

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to retrieve API key.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid request type.")

            except:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to make request.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")