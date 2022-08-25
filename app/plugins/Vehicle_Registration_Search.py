#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Plugin_Name: str = "Vehicle Registration"
        self.Concat_Plugin_Name: str = "vehicleregistration"
        self.States = ['QLD', 'VIC', 'SA', 'WA', 'TAS', 'ACT', 'NT', 'NSW']
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Main_Converted": ".html"}
        self.Domain: str = "general-insurance.coles.com.au"
        self.Result_Type: str = "Vehicle Details"

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
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)

                for State in self.States:
                    Post_URL = f'https://{self.Domain}/bin/wesfarmers/search/vehiclerego'
                    data: str = '''{"isRegoSearch":"YES","regoSearchCount":2,"regoMatchCount":1,"regoSearchFailureCount":0,"failPaymentAttempts":0,"pauseStep":"false","campaignBaseURL":"https://secure.colesinsurance.com.au/campaignimages/","sessionState":"OPEN","sessionStep":"0","policyHolders":[],"updateSessionURL":"http://dev.gtw.gp-mdl.auiag.corp:9000/sys/colessessionservice/motor/v1/update-session","insuranceType":"COMP","startDate":"03/07/2019","drivers":[{"driverRef":"MainDriver","yearsLicenced":{"vehRef":"veh1"}}],"priceBeatAttemptsRemaining":"2","currentInsurerOptions":[{"id":"AAMI","value":"AAMI","text":"AAMI"},{"id":"Allianz","value":"Allianz","text":"Allianz"},{"id":"Apia","value":"Apia","text":"Apia"},{"id":"Bingle","value":"Bingle","text":"Bingle"},{"id":"Broker","value":"Broker","text":"Broker"},{"id":"BudgDirect","value":"BudgDirect","text":"Budget Direct"},{"id":"Buzz","value":"Buzz","text":"Buzz"},{"id":"CGU","value":"CGU","text":"CGU"},{"id":"Coles","value":"Coles","text":"Coles"},{"id":"CommInsure","value":"CommInsure","text":"CommInsure"},{"id":"GIO","value":"GIO","text":"GIO"},{"id":"HBF","value":"HBF","text":"HBF"},{"id":"JustCar","value":"JustCar","text":"Just Car"},{"id":"NRMA","value":"NRMA","text":"NRMA"},{"id":"Progress","value":"Progress","text":"Progressive"},{"id":"QBE","value":"QBE","text":"QBE"},{"id":"RAA","value":"RAA","text":"RAA"},{"id":"RAC","value":"RAC","text":"RAC"},{"id":"RACQ","value":"RACQ","text":"RACQ"},{"id":"RACT","value":"RACT","text":"RACT"},{"id":"RACV","value":"RACV","text":"RACV"},{"id":"Real","value":"Real","text":"Real"},{"id":"SGIC","value":"SGIC","text":"SGIC"},{"id":"SGIO","value":"SGIO","text":"SGIO"},{"id":"Shannons","value":"Shannons","text":"Shannons"},{"id":"Suncorp","value":"Suncorp","text":"Suncorp"},{"id":"Youi","value":"Youi","text":"Youi"},{"id":"None","value":"None","text":"Car is not currently insured"},{"id":"Dontknow","value":"Dontknow","text":"Don't Know"},{"id":"Other","value":"Other","text":"Other"}],"coverLevelOptions":[{"id":"Gold","value":"Comprehensive Plus Car Insurance","text":"Comprehensive Plus Car Insurance","flagname":"NRMA","code":"Gold","order":"1"},{"id":"Gold1","value":"Gold Comprehensive Car Insurance","text":"Gold Comprehensive Car Insurance","flagname":"BudgDirect","code":"Gold","order":"1"},{"id":"Standard2","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"SGIC","code":"Standard","order":"2"},{"id":"Gold6","value":"Comprehensive Advantages Car Insurance","text":"Comprehensive Advantages Car Insurance","flagname":"Suncorp","code":"Gold","order":"1"},{"id":"Standard","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"GIO","code":"Standard","order":"2"},{"id":"Standard0","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"NRMA","code":"Standard","order":"2"},{"id":"Gold4","value":"Comprehensive Plus Car Insurance","text":"Comprehensive Plus Car Insurance","flagname":"SGIC","code":"Gold","order":"1"},{"id":"Standard5","value":"Full Comprehensive Car Insurance","text":"Full Comprehensive Car Insurance","flagname":"1300 Insurance","code":"Standard","order":"2"},{"id":"Gold5","value":"Comprehensive Plus Car Insurance","text":"Comprehensive Plus Car Insurance","flagname":"SGIO","code":"Gold","order":"1"},{"id":"Gold2","value":"Platinum Car Insurance","text":"Platinum Car Insurance","flagname":"GIO","code":"Gold","order":"1"},{"id":"Standard3","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"SGIO","code":"Standard","order":"2"},{"id":"Gold3","value":"Complete Care Motor Insurance","text":"Complete Care Motor Insurance","flagname":"RACV","code":"Gold","order":"1"},{"id":"Standard4","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"Suncorp","code":"Standard","order":"2"},{"id":"Gold0","value":"Gold Comprehensive Car Insurance","text":"Gold Comprehensive Car Insurance","flagname":"1300 Insurance","code":"Gold","order":"1"},{"id":"Standard1","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"RACV","code":"Standard","order":"2"}],"riskAddress":{"latitude":"-33.86579240","locality":"PYRMONT","postcode":"2009","extraAddressInfo":{"houseNumber":"1","lotNumber":"1","streetName":"HARRIS","streetSuffix":"STREET","unitNumber":"1"},"state":"''' + State + '''","line3":null,"isVerificationRequired":null,"gnaf":"GANSW709981139","line2":null,"line1":"1 Harris Street","longitude":"151.19109690","displayString":"1 HARRIS STREET, PYRMONT, NSW, 2009"},"postcode":{"latitude":"-33.86579240","locality":"PYRMONT","postcode":"2009","extraAddressInfo":{"houseNumber":"1","lotNumber":"1","streetName":"HARRIS","streetSuffix":"STREET","unitNumber":"1"},"state":"''' + State + '''","line3":null,"isVerificationRequired":null,"gnaf":"GANSW709981139","line2":null,"line1":"1 Harris Street","longitude":"151.19109690","displayString":"1 HARRIS STREET, PYRMONT, NSW, 2009"},"carRegistration":"''' + Query + '''","chooseValue":"","whatValueInsure":"Marketvalue","whatValueInsure_value":{"key":"Marketvalue","value":"Market Value"}}'''
                    headers = {'Content-Type': 'ext/plain;charset=UTF-8',
                               'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate, br',
                               'Referer': f'https://{self.Domain}/motor/get-quote',
                               'Origin': f'https://{self.Domain}', 'Host': self.Domain}
                    Registration_Response = Common.Request_Handler(url=Post_URL, method="POST", Data=data, Optional_Headers=headers)
                    JSON_Object = Common.JSON_Handler(Registration_Response)
                    Registration_Response = JSON_Object.To_JSON_Loads()
                    Indented_JSON_Response = JSON_Object.Dump_JSON()

                    try:
                        Title = f"{self.Plugin_Name} | " + Registration_Response['vehicles'][0]['make'] + " " + Registration_Response['vehicles'][0]['model']
                        Item_URL = Post_URL + "?" + Query

                        if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Indented_JSON_Response, Title.replace(" ", "-"), self.The_File_Extensions["Main"])
                            HTML_Output_File_Data = General.JSONDict_to_HTML(Registration_Response["vehicles"], Indented_JSON_Response, f"{self.Plugin_Name} Query {Query}")
                            HTML_Output_File = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, HTML_Output_File_Data, Title.replace(" ", "-"), self.The_File_Extensions["Main_Converted"])

                            if Output_file and HTML_Output_File:
                                Output_Connections.Output([Output_file, HTML_Output_File], Item_URL, Title, self.Concat_Plugin_Name)
                                Data_to_Cache.append(Item_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    except:
                        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - No result found for given query {Query} for state {State}.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")