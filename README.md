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