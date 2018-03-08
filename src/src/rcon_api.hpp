#ifndef RCON_API_H
#define RCON_API_H

#include <string>
#include <vector>

struct PlayerInfo {
    std::string number;
    std::string player_name;
    std::string guid;       //can be wrong until verified
    std::string ip;
    int port;
    bool verified;

    //These are not guaranteed to be correct
    int ping;
    bool lobby;

    //only if vpn check is enabled
    std::string country_code;
    std::string country;
    std::string isp;
};

enum TaskType {
    GLOBALMESSAGE,
    KICKALL,
    SHUTDOWN,
    LOCK,
    UNLOCK
};


struct rcon_api {
    bool(*is_logged_in)();

    void(*add_task)(const TaskType& _type, const std::string& _data, bool _repeat, int _seconds_until);

    void(*kick_all)();
    void(*send_command)(const std::string& _command);

    void(*add_ban)(const std::string& _guid);
    void(*remove_ban)(const std::string& _guid);

    void(*add_to_whitelist)(const std::string& _guid);
    void(*remove_from_whitelist)(const std::string& _guid);

    std::vector<PlayerInfo>(*get_players)();
};

#endif // !RCON_API_H
