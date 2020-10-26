#!/usr/bin/env python3
import requests, json, os, logging, plugins.common.General as General

Plugin_Name = "Vehicle-Registration-Search"
Concat_Plugin_Name = "registrationsearch"
States = ['QLD', 'VIC', 'SA', 'WA', 'TAS', 'ACT', 'NT', 'NSW']
The_File_Extension = ".json"
Domain = "general-insurance.coles.com.au"

def Search(Query_List, Task_ID):

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
            Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Vehicle Details", Task_ID, Concat_Plugin_Name)

            for State in States:
                Post_URL = f'https://{Domain}/bin/wesfarmers/search/vehiclerego'
                data = '''{"isRegoSearch":"YES","regoSearchCount":2,"regoMatchCount":1,"regoSearchFailureCount":0,"failPaymentAttempts":0,"pauseStep":"false","campaignBaseURL":"https://secure.colesinsurance.com.au/campaignimages/","sessionState":"OPEN","sessionStep":"0","policyHolders":[],"updateSessionURL":"http://dev.gtw.gp-mdl.auiag.corp:9000/sys/colessessionservice/motor/v1/update-session","insuranceType":"COMP","startDate":"03/07/2019","drivers":[{"driverRef":"MainDriver","yearsLicenced":{"vehRef":"veh1"}}],"priceBeatAttemptsRemaining":"2","currentInsurerOptions":[{"id":"AAMI","value":"AAMI","text":"AAMI"},{"id":"Allianz","value":"Allianz","text":"Allianz"},{"id":"Apia","value":"Apia","text":"Apia"},{"id":"Bingle","value":"Bingle","text":"Bingle"},{"id":"Broker","value":"Broker","text":"Broker"},{"id":"BudgDirect","value":"BudgDirect","text":"Budget Direct"},{"id":"Buzz","value":"Buzz","text":"Buzz"},{"id":"CGU","value":"CGU","text":"CGU"},{"id":"Coles","value":"Coles","text":"Coles"},{"id":"CommInsure","value":"CommInsure","text":"CommInsure"},{"id":"GIO","value":"GIO","text":"GIO"},{"id":"HBF","value":"HBF","text":"HBF"},{"id":"JustCar","value":"JustCar","text":"Just Car"},{"id":"NRMA","value":"NRMA","text":"NRMA"},{"id":"Progress","value":"Progress","text":"Progressive"},{"id":"QBE","value":"QBE","text":"QBE"},{"id":"RAA","value":"RAA","text":"RAA"},{"id":"RAC","value":"RAC","text":"RAC"},{"id":"RACQ","value":"RACQ","text":"RACQ"},{"id":"RACT","value":"RACT","text":"RACT"},{"id":"RACV","value":"RACV","text":"RACV"},{"id":"Real","value":"Real","text":"Real"},{"id":"SGIC","value":"SGIC","text":"SGIC"},{"id":"SGIO","value":"SGIO","text":"SGIO"},{"id":"Shannons","value":"Shannons","text":"Shannons"},{"id":"Suncorp","value":"Suncorp","text":"Suncorp"},{"id":"Youi","value":"Youi","text":"Youi"},{"id":"None","value":"None","text":"Car is not currently insured"},{"id":"Dontknow","value":"Dontknow","text":"Don't Know"},{"id":"Other","value":"Other","text":"Other"}],"coverLevelOptions":[{"id":"Gold","value":"Comprehensive Plus Car Insurance","text":"Comprehensive Plus Car Insurance","flagname":"NRMA","code":"Gold","order":"1"},{"id":"Gold1","value":"Gold Comprehensive Car Insurance","text":"Gold Comprehensive Car Insurance","flagname":"BudgDirect","code":"Gold","order":"1"},{"id":"Standard2","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"SGIC","code":"Standard","order":"2"},{"id":"Gold6","value":"Comprehensive Advantages Car Insurance","text":"Comprehensive Advantages Car Insurance","flagname":"Suncorp","code":"Gold","order":"1"},{"id":"Standard","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"GIO","code":"Standard","order":"2"},{"id":"Standard0","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"NRMA","code":"Standard","order":"2"},{"id":"Gold4","value":"Comprehensive Plus Car Insurance","text":"Comprehensive Plus Car Insurance","flagname":"SGIC","code":"Gold","order":"1"},{"id":"Standard5","value":"Full Comprehensive Car Insurance","text":"Full Comprehensive Car Insurance","flagname":"1300 Insurance","code":"Standard","order":"2"},{"id":"Gold5","value":"Comprehensive Plus Car Insurance","text":"Comprehensive Plus Car Insurance","flagname":"SGIO","code":"Gold","order":"1"},{"id":"Gold2","value":"Platinum Car Insurance","text":"Platinum Car Insurance","flagname":"GIO","code":"Gold","order":"1"},{"id":"Standard3","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"SGIO","code":"Standard","order":"2"},{"id":"Gold3","value":"Complete Care Motor Insurance","text":"Complete Care Motor Insurance","flagname":"RACV","code":"Gold","order":"1"},{"id":"Standard4","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"Suncorp","code":"Standard","order":"2"},{"id":"Gold0","value":"Gold Comprehensive Car Insurance","text":"Gold Comprehensive Car Insurance","flagname":"1300 Insurance","code":"Gold","order":"1"},{"id":"Standard1","value":"Comprehensive Car Insurance","text":"Comprehensive Car Insurance","flagname":"RACV","code":"Standard","order":"2"}],"riskAddress":{"latitude":"-33.86579240","locality":"PYRMONT","postcode":"2009","extraAddressInfo":{"houseNumber":"1","lotNumber":"1","streetName":"HARRIS","streetSuffix":"STREET","unitNumber":"1"},"state":"''' + State + '''","line3":null,"isVerificationRequired":null,"gnaf":"GANSW709981139","line2":null,"line1":"1 Harris Street","longitude":"151.19109690","displayString":"1 HARRIS STREET, PYRMONT, NSW, 2009"},"postcode":{"latitude":"-33.86579240","locality":"PYRMONT","postcode":"2009","extraAddressInfo":{"houseNumber":"1","lotNumber":"1","streetName":"HARRIS","streetSuffix":"STREET","unitNumber":"1"},"state":"''' + State + '''","line3":null,"isVerificationRequired":null,"gnaf":"GANSW709981139","line2":null,"line1":"1 Harris Street","longitude":"151.19109690","displayString":"1 HARRIS STREET, PYRMONT, NSW, 2009"},"carRegistration":"''' + Query + '''","chooseValue":"","whatValueInsure":"Marketvalue","whatValueInsure_value":{"key":"Marketvalue","value":"Market Value"}}'''
                headers = {'Content-Type': 'ext/plain;charset=UTF-8',
                           'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.90 Safari/537.36',
                           'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate, br',
                           'Referer': f'https://{Domain}/motor/get-quote',
                           'Origin': f'https://{Domain}', 'Host': Domain}
                Registration_Response = requests.post(Post_URL, data=data, headers=headers).text
                Registration_Response = json.loads(Registration_Response)

                try:
                    Title = "Vehicle Registration | " + Registration_Response['vehicles'][0]['make'] + " " + Registration_Response['vehicles'][0]['model']
                    Item_URL = Post_URL + "?" + Query

                    if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, json.dumps(Registration_Response, indent=4, sort_keys=True), Title.replace(" ", "-"), The_File_Extension)

                        if Output_file:
                            Output_Connections.Output([Output_file], Item_URL, Title, Concat_Plugin_Name)
                            Data_to_Cache.append(Item_URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                except:
                    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - No result found for given query {Query} for state {State}.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")