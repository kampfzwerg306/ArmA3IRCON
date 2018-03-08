#pragma once

#include <unordered_map>
#include <mutex>

#include "rcon_api.hpp"
#include "json.hpp"
#include "utils.hpp"
#include <unordered_set>
#include <optional>
#include <memory>
#include <future>
#include <queue>
#include <cstdio>
#include <cstdlib>
#include <cstdint>  // Includes ::std::uint32_t


#include "UDP.hpp"

#define CRCPP_USE_CPP11
#include "crc.hpp"

#ifndef _REST_STANDALONE_COMPILE
#include "plugin_interface.hpp"
#else
#include "rest_client.hpp"
#endif

class RCON {

public:
	
    RCON(const std::string& host, int port, const std::string& pw, bool delayed);
	~RCON();
	
    void start();

	void send_command(const std::string& command);

    void remove_ban(const std::string& player_guid);
	void add_ban(const std::string& player_guid);

    bool is_logged_in();

    void set_whitelist_enabled(bool _state);
    void set_white_list(const std::vector<std::string>& _guids);
    void add_to_whitelist(const std::string& _guid);
    void remove_from_whitelist(const std::string& _guid);

    void set_open_slots(int _slots);
    void set_max_players(int _slots);
    void set_white_list_kick_message(const std::string & _msg);

    std::vector<PlayerInfo> get_players();

    void add_task(const TaskType& _type, const std::string& _data, bool _repeat, int _seconds_until);

    void kick_all();
    void enable_auto_reconnect();
    void enable_vpn_detection();
    void set_vpn_detect_kick_msg(const std::string& _msg);
    void set_iphub_api_key(const std::string& _msg);
    void add_vpn_detection_guid_exception(const std::string& _guid);
    void enable_vpn_suspecious_kicks();

#ifndef _REST_STANDALONE_COMPILE
    void set_rest_api(rest_api * _rest);
#endif // !_REST_STANDALONE_COMPILE


private:

    void connect();

    enum message_type {
        LOGIN = 0x00,
        SERVER = 0x01,
        CHAT = 0x02
    };
    struct Packet {
        std::string command;
        message_type type;
    };
    
    UDP_Socket * socket;
	
	unsigned int port;
	std::string host;
	std::string password;

    void bind();
	bool loggedin = false;

    bool send_heart_beat = true;
    std::chrono::time_point<std::chrono::system_clock> last_heart_beat;
    std::chrono::time_point<std::chrono::system_clock> last_ACK;

    bool run_thread = true;
    std::thread worker;

    bool auto_reconnect = false;
    short auto_reconnect_trys = 5;
    std::chrono::seconds auto_reconnect_delay = std::chrono::seconds(30);

    std::string remove_null_terminator(std::string _str);
    std::string make_be_message(const std::string&, const message_type&);
    void send_packet(const Packet& rcon_packet);
    void send_packet(const Packet& rcon_packet, std::function<void(int)> _handle_sent);
    
    void handle_disconnect();
    void refresh_players();
    
    void handle_rec(const std::string& received, size_t bytes_received);
    void handle_sent(int bytes_sent);

    void chat_message(const std::string& _response);
    void on_player_connect(const std::string & _player_number, const std::string & _player_name, const std::string& _ip, int _port);
    void on_player_disconnect(const std::string & _player_number, const std::string & _player_name);
    void on_player_verified_guid(const std::string & _player_number, const std::string & _player_name, const std::string & _player_guid);
    void login_response(const std::string& _response);
    void server_response(const std::string& _response);
    std::unordered_map< unsigned char, std::pair<unsigned char, std::vector<std::string> > > msg_cache;
    std::mutex msg_cache_mutex;
    char current_seq_num = 0x00;

    void process_message(unsigned char sequence_number, const std::string& message);
    void process_message_players(const std::vector<std::string>& tokens);
    void process_message_missions(const std::vector<std::string>& tokens);
    void process_message_bans(const std::vector<std::string>& tokens);
    
    bool is_bad_player_string(const std::string& player_name);
    bool is_whitelisted_player(const std::string& player_guid);
    bool is_vpn_whitelisted_player(const std::string& player_guid);
	
    // Player Name / BEGuid
	std::unordered_map<std::string, PlayerInfo> players;
    std::mutex player_mutex;

    /*
    *   FEATURES
    */

    struct WhitelistSettings
    {
        //constants
        bool enable = false;
        int open_slots = 0;
        std::atomic<int> current_players = 0;
        int max_players = 100;
        std::string kick_message = "Not whitelisted!";
        std::unordered_set<std::string> whitelisted_guids;
        std::mutex whitelist_mutex;
    };
    WhitelistSettings whitelist_settings;

    struct IPInfo {
        std::string isp;
        std::string country;
        std::string country_code;
        int block = 0;

        IPInfo(const std::string& _isp, const std::string& _country, const std::string& _country_code, int _block) : 
            isp(_isp), 
            country(_country), 
            country_code(_country_code), 
            block(_block) {}
    };
    std::optional<IPInfo> check_ip_cache(const std::string& ip);
    void check_ip(const std::string& _player_name);

    short ip_counter_this_minute = 0;
    std::chrono::time_point<std::chrono::system_clock> ip_last_time_intervall;
    std::queue<std::string> ip_check_tasks;
    std::mutex ip_check_tasks_mutex;

    struct VPNDetection {
        bool enable = false;
        bool kick_if_suspecious = false;
        std::string kick_message = "VPN/Proxy Detected!";
        std::string api_key = "";
        std::unordered_set<std::string> exception_guids;
        std::unordered_map<std::string, IPInfo> _ip_cache;
        std::mutex mutex;
    };
    VPNDetection vpn;

#ifndef _REST_STANDALONE_COMPILE
    rest_api * rest = nullptr;
#endif

    struct Task {
        TaskType type;
        std::string data;
        bool repeat;
        int seconds;
        std::chrono::time_point<std::chrono::system_clock> exec_at;
        Task * next_task = nullptr;
    };
    Task * task_head = nullptr;
    std::mutex task_mutex;

    void insert_task(Task * _new_task);
};