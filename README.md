# ArmA 3 IRCON  
ArmA 3 IRCON is a intercept based RCON Plugin which can also be compiled as a standalone cli program.  

## Features
The main features are:  
- UDP Socket class for general purpose use
- RCON Class keeps track of currently connected players
- Usual RCON abilities via send_command (any BERcon command will work that way..)
- Whitelisting
- Reserved Slots
- Usual Bad Character name checking to avoid database corruption/injections
- Inbuild VPN/Proxy Check API connection to IPHub (API Key needed (Free Plan supports 25queries/min))
- Plugin interface

## What I will not do

Create any sort of sqf command integration for the plugin api. Simply because this is really dangerous to the server.
What could be done in the future is to integrate events for player join/disconnect simply because this is quite useful in some persistent scenerios.

## Building
Just like intercept itself. Create a folder inside the repo (name it proj, thats ignored in the repo already). open a terminal there and execute: cmake .. (-G "Visual Studio 15 2017 Win64" for 64 bit). This will create the makefiles (should be Linux compatible since its based on asio, nlohmann json and crc (uhmm.. see the credits there). Run the makefiles as usual. This will build into the build folder. After that create the needed addon (addonstructure is given in the arma folder), inside @RCON create a folder named intercept and place the built dll in there, place the intercept stuff as in their tutorial. Then create a folder in the ArmA root folder called config and place the rcon_config.cfg in there and edit it to your likings. Its a json-format with all examples given.. if you do something wrong in there, the game will most likly crash on startup.
