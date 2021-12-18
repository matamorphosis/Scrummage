import json

JSON_File = open("./static/json/plugin_definitions.json", "r")
Valid_Plugins = json.load(JSON_File)