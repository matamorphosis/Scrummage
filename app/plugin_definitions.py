import json, os

def Get_Definitions():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    JSON_File = open(os.path.join(File_Dir, "static/json/plugin_definitions.json"), "r")
    return json.load(JSON_File)