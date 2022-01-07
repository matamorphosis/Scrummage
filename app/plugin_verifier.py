import importlib, plugin_definitions, plugins.common.General as General, plugins.common.Common as Common
# from typing import Dict

class Plugin_Verifier:

    def __init__(self, Plugin_Name, Task_ID, Query, Limit, Custom_Query=None):
        self.plugin_name = Plugin_Name
        self.custom_query = Custom_Query
        self.query = Query
        self.limit = Limit
        self.task_id = Task_ID

    def Verify_Plugin(self, Scrummage_Working_Directory, Load_Config_Only=False):
    
        try:
            Plugins_Dictionary = plugin_definitions.Get(Scrummage_Working_Directory)

            try:

                def Output_API_Checker(Plugin_Object, Plugin_Name):
                    In_Dict = False
                    Result = None

                    for API_Key, API_Value in Plugins_Dictionary.items():

                        if Plugin_Name == API_Key and API_Value["Requires_Configuration"] == True:
                            In_Dict = True
                            Result = Plugin_Object.Load_Configuration()

                    if In_Dict:
                        return Result

                    else:
                        return True

                if Load_Config_Only:

                    if self.plugin_name in Plugins_Dictionary:
                        Dict_Item = Plugins_Dictionary[self.plugin_name]
                        Kwargs = {}
                        Func_Kwargs = {}

                        for Key in ["Requires_Limit", "Type", "Alphabets", "Comprehensive"]:

                            if Key in Dict_Item and Key == "Type":
                                Kwargs[Key] = Dict_Item[Key]

                            elif Key in Dict_Item and Key == "Requires_Limit" and Dict_Item.get(Key):
                                Kwargs["Limit"] = self.limit

                            elif Key in Dict_Item and Key != "Requires_Limit":
                                Func_Kwargs[Key] = Dict_Item[Key]

                        if "Custom_Search" in Dict_Item:
                            Search_Option = Dict_Item["Custom_Search"]
                            
                        else:
                            Search_Option = "Search"

                        Class = importlib.import_module(Dict_Item["Module"])

                        if self.custom_query:
                            Plugin_Object = Class.Plugin_Search(self.custom_query, self.task_id, **Kwargs)

                        else:
                            Plugin_Object = Class.Plugin_Search(self.query, self.task_id, **Kwargs)

                        Result = Output_API_Checker(Plugin_Object, self.plugin_name)

                        if Result:
                            return True

                        else:
                            return False

                    else:
                        print(f"{Common.Date()} - Plugin Verifier - Invalid plugin provided.")

                else:

                    if self.plugin_name in Plugins_Dictionary:
                        Dict_Item = Plugins_Dictionary[self.plugin_name]
                        Kwargs = {}
                        Func_Kwargs = {}

                        for Key in ["Requires_Limit", "Type", "Alphabets", "Comprehensive"]:

                            if Key in Dict_Item and Key == "Type":
                                Kwargs[Key] = Dict_Item[Key]

                            elif Key in Dict_Item and Key == "Requires_Limit" and Dict_Item.get(Key):
                                Kwargs["Limit"] = self.limit

                            elif Key in Dict_Item and Key != "Requires_Limit":
                                Func_Kwargs[Key] = Dict_Item[Key]

                        if "Custom_Search" in Dict_Item:
                            Search_Option = Dict_Item["Custom_Search"]
                            
                        else:
                            Search_Option = "Search"

                        Class = importlib.import_module(Dict_Item["Module"])

                        if self.custom_query:
                            Plugin_Object = Class.Plugin_Search(self.custom_query, self.task_id, **Kwargs)

                        else:
                            Plugin_Object = Class.Plugin_Search(self.query, self.task_id, **Kwargs)

                        Result = Output_API_Checker(Plugin_Object, self.plugin_name)

                        if Result:
                            return {"Object": Plugin_Object, "Search Option": Search_Option, "Function Kwargs": Func_Kwargs}

                        else:
                            return False

                    else:
                        print(f"{Common.Date()} - Plugin Verifier - Invalid plugin provided.")

            except Exception as e:
                print(f"{Common.Date()} - Plugin Verifier - {str(e)}.")
                
        except Exception as e:
            print(f"{Common.Date()} - Plugin Verifier - {str(e)}.")