//#define TEST_APP

#include "rcon_api.hpp"
#include "RCON.hpp"

#include "logging.hpp"
#include "json.hpp"

//#include <experimental\filesystem>
#include <fstream>
#include <string>
#include <streambuf>

#ifndef TEST_APP
#include "intercept.hpp"
#include "utils_intercept.hpp"

#ifndef _REST_STANDALONE_COMPILE
#include "plugin_interface.hpp"
#endif

#endif


static bool functions_registered = false;
static std::shared_ptr<RCON> rcon = nullptr;

bool is_logged_in_api() {
    return rcon && rcon->is_logged_in();
}

void add_task_api(const TaskType& _type, const std::string& _data, bool _repeat, int _seconds_until) {
    if (rcon) rcon->add_task(_type,_data,_repeat,_seconds_until);
}

void kick_all_api() {
    if (rcon) rcon->kick_all();
}

void send_command_api(const std::string& _command) {
    if (rcon) rcon->send_command(_command);
}

void add_ban_api(const std::string& _guid) {
    if (rcon) rcon->add_ban(_guid);
}

void remove_ban_api(const std::string& _guid) {
    if (rcon) rcon->remove_ban(_guid);
}

void add_to_whitelist_api(const std::string& _guid) {
    if (rcon) rcon->add_to_whitelist(_guid);
}

void remove_from_whitelist_api(const std::string& _guid) {
    if (rcon) rcon->remove_from_whitelist(_guid);
}

std::vector<PlayerInfo> get_players_api() {
    if (rcon) return rcon->get_players();
    else return {};
}

static rcon_api iface_decl{
    is_logged_in_api,
    add_task_api,
    kick_all_api,
    send_command_api,
    add_ban_api,
    remove_ban_api,
    add_to_whitelist_api,
    remove_from_whitelist_api,
    get_players_api
};

#ifndef TEST_APP
void CDECL intercept::pre_start() {
    LOG(DEBUG, "Plugin loaded!");

    //auto _path = std::experimental::filesystem::current_path().string();
    //LOG(DEBUG, "Working Directory is: " + _path);
    
    nlohmann::json config;
    
    std::ifstream config_file ("config/rcon_config.cfg");
    
    if (config_file.is_open()) {
        std::string _buf;

        config_file.seekg(0, std::ios::end);
        _buf.reserve(config_file.tellg());
        config_file.seekg(0, std::ios::beg);

        _buf.assign((std::istreambuf_iterator<char>(config_file)),
            std::istreambuf_iterator<char>());

        LOG(DEBUG, "Parsing Config");
        config = nlohmann::json::parse(_buf);
        LOG(DEBUG, "Parsing Config done");
    }


    std::string _ip, _password;
    int _port;

    _ip = config.value("host", "127.0.0.1");

    _port = config.value("port",2302);
    
    _password = config.value("password","changeme");
    
    rcon = std::make_shared<RCON>(
        _ip,
        _port,
        _password,
        true
    );

    if (config.value("autoreconnect",false)) {
        rcon->enable_auto_reconnect();
    }

    nlohmann::json _whitelist = config.value("whitelist",nlohmann::json::object());
    if (_whitelist.value("enable",false)) {
        rcon->set_whitelist_enabled(true);

        nlohmann::json _guids = _whitelist.value("guids",nlohmann::json::array());
        for (nlohmann::json::iterator it = _guids.begin(); it != _guids.end(); ++it) {
            try {
                rcon->add_to_whitelist(
                    it.value().get<std::string>()
                );
            }
            catch (...) {

            }
        }

        rcon->set_open_slots(_whitelist.value("openslots",0));
        rcon->set_max_players(_whitelist.value("maxplayers",100));
    }
    

    nlohmann::json _vpnd = config.value("vpndetection",nlohmann::json::object());
    if (_vpnd.value("enable",false)) {
            
#ifndef _REST_STANDALONE_COMPILE
        auto _rest_if = intercept::client::host::request_plugin_interface("rest_api", 1);
        if (!_rest_if) {
            LOG(DEBUG, "DID NOT FIND REST INTERFACE! CHECK INSTALLATION!");
            std::exit(0);
        }
        else {
            rcon->set_rest_api(static_cast<rest_api*>(*_rest_if));
        }
#endif
        rcon->enable_vpn_detection();

        auto _guids = _vpnd.value("exceptedguids",nlohmann::json::array());
        for (nlohmann::json::iterator it = _guids.begin(); it != _guids.end(); ++it) {
            try {
                rcon->add_vpn_detection_guid_exception(
                    it.value().get<std::string>()
                );
            }
            catch (...) {

            }
        }
        
        rcon->set_iphub_api_key(_vpnd.value("apikey",""));

        if (_vpnd.at("kicksuspecious").get<bool>()) {
            rcon->enable_vpn_suspecious_kicks();
        }
    }

    
    nlohmann::json _tasks = config.value("tasks", nlohmann::json::array());
        
    for (nlohmann::json::iterator it = _tasks.begin(); it != _tasks.end(); ++it) {
            
        std::string _type;
        std::string _data;
        bool _repeat;
        int _seconds;
            
        try {
            //any error makes the task invalid
            _type = it.value().at("type").get<std::string>();
            _repeat = it.value().at("repeat").get<bool>();
            _seconds = it.value().at("seconds").get<int>();
        }
        catch (...) {
            continue;
        }

        _data = it.value().value("data","");
            

        if (_type == "GLOBALCHAT") {
            rcon->add_task(TaskType::GLOBALMESSAGE, _data, _repeat, _seconds);
        }
        else if (_type == "KICKALL") {
            rcon->add_task(TaskType::KICKALL, _data, _repeat, _seconds);
        }
        else if (_type == "SHUTDOWN") {
            rcon->add_task(TaskType::SHUTDOWN, _data, _repeat, _seconds);
        }

    }

    rcon->start();

    if (functions_registered) return;
    functions_registered = true;
}

void CDECL intercept::pre_init() {

}

void CDECL intercept::post_init() {

}

int CDECL intercept::api_version() {
    return 1;
}

void CDECL intercept::register_interfaces() {
    LOG(DEBUG, "ADDING INTERFACE spawner_iface");
    auto _result = intercept::client::host::register_plugin_interface("rcon_api"sv, 1, &iface_decl);

    if (_result == intercept::types::register_plugin_interface_result::success) {
        LOG(DEBUG, "ADDING INTERFACE SUCCESS");
    }
    else if (_result == intercept::types::register_plugin_interface_result::interface_already_registered) {
        LOG(DEBUG, "ADDING INTERFACE FAILED ALREADY REGISTERED");
    }
    else if (_result == intercept::types::register_plugin_interface_result::invalid_interface_class) {
        LOG(DEBUG, "ADDING INTERFACE FAILED INVALID CLASS");
    }
}

DLL_MAIN_LOGGING("RCON")

DLL_MAIN_ENTRY

#else 

#include <iostream>
int main(int, char**) {

    rcon = std::make_shared<RCON>(
        "127.0.0.1",
        1337,
        "test",
        true
    );

    rcon->enable_auto_reconnect();

    rcon->enable_vpn_detection();

    rcon->set_iphub_api_key("XXXX");

    rcon->start();

    std::thread([]() {
        while (!rcon->is_logged_in()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        std::cout << "Logged in!" << std::endl;
    }).detach();

    std::string _buff;
    
    while (true) {

        std::cin.clear();
        std::cin >> _buff;

        if (_buff == "players") {
            rcon->send_command("players");
        }
        else if (_buff == "chat") {
            std::cin.clear();
            std::cin >> _buff;
            rcon->send_command("say -1 " + _buff);
        }
        else if (_buff == "bans") {
            rcon->send_command("bans");
        }
        else if (_buff == "missions") {
            rcon->send_command("missions");
        }
        else if (_buff == "loadbans") {
            rcon->send_command("loadbans");
        }
        else if (_buff == "exit") {
            break;
        }

    }

}
#endif