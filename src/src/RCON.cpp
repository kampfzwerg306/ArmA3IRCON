#include "RCON.hpp"

std::string RCON::remove_null_terminator(std::string _str) {
    if (_str.size() > 0 && _str[_str.size() - 1] == '\0') {
        _str.erase(_str.size() - 1);
    }
    return _str;
}

RCON::RCON(const std::string& _ip, int _port, const std::string& _pw, bool _delayed = false) : 
    host(_ip), 
    port(_port), 
    password(_pw) {

    if (host == "") {
        this->host = "127.0.0.1";
    }
    
    if (port <= 0) {
        port = 2302;
    }
    
    password = remove_null_terminator(password);
    
    start();

}

void RCON::start() {
    
    socket = new UDP_Socket(host, port, [this]() {
        handle_disconnect();
    });

    auto _now = std::chrono::system_clock::now();
    ip_last_time_intervall = _now;
    last_heart_beat = last_ACK = _now - std::chrono::seconds(30);


    if (socket->is_connected()) {

        bind();

    }
    else {

        loggedin = false;

#ifdef TEST_APP
        std::cout << "Initial connect failed!" << std::endl;
#endif

    }

    worker = std::thread([this]() {

        std::string cmd = make_be_message("", RCON::message_type::SERVER);

        while (run_thread) {

            std::this_thread::sleep_for(std::chrono::seconds(1));

            //check for ACK of last heart beat
            auto _now = std::chrono::system_clock::now();
            auto _duration = std::chrono::duration_cast<std::chrono::seconds>(_now - last_heart_beat);

            //received no ACK since 5 sec
            if (last_heart_beat > last_ACK && _duration > std::chrono::seconds(5)) {
                handle_disconnect();
            }

            //auto reconnect
            if (!loggedin && auto_reconnect) {

                while (auto_reconnect_trys > 0) {

                    socket->reconnect();

                    if (socket->is_connected()) {
                        bind();
                    }

                    std::this_thread::sleep_for(auto_reconnect_delay);

                    if (!loggedin) {
                        auto_reconnect_trys--;
                    }
                    else {
                        auto_reconnect_trys = 5;
                        break;
                    }
                }

            }

            if (loggedin) {

                //check heart beat
                _duration = std::chrono::duration_cast<std::chrono::seconds>(_now - last_heart_beat);
                if (_duration >= std::chrono::seconds(25)) {
                    socket->send(
                        cmd,
                        //handle sent
                        [this](int _bytes) {
                        handle_sent(_bytes);
                    }
                    );
                    last_heart_beat = std::chrono::system_clock::now();
#ifdef TEST_APP
                    std::cout << "HEARTBEAT!" << std::endl;
#endif // TEST_APP

                }

                //check ip intervall
                _duration = std::chrono::duration_cast<std::chrono::seconds>(_now - ip_last_time_intervall);
                if (_duration > std::chrono::seconds(60)) {
                    ip_counter_this_minute = 24; //free plan limit
                    ip_last_time_intervall = _now;
                }

                //check ip tasks
                if (ip_counter_this_minute > 0) {
                    std::string _task;
                    {
                        std::lock_guard<std::mutex> lock(ip_check_tasks_mutex);
                        if (!ip_check_tasks.empty()) {
                            _task = ip_check_tasks.front();
                            ip_check_tasks.pop();
                        }
                    }

                    //this will also decrease the conuter if its not cached
                    if (_task != "") check_ip(_task);
                }


                //check tasks
                {
                    std::lock_guard<std::mutex> lock(task_mutex);
                    if (task_head != nullptr) {
                        if (task_head->exec_at <= _now) {
                            switch (task_head->type) {
                            case (TaskType::GLOBALMESSAGE): {
                                send_command("say -1 " + task_head->data);
                                break;
                            }
                            case(TaskType::KICKALL): {
                                kick_all();
                                break;
                            }
                            case(TaskType::SHUTDOWN): {
                                std::exit(0);
                                break;
                            }
                            }

                            auto _cur = task_head;
                            task_head = task_head->next_task;

                            if (_cur->repeat) {
                                _cur->exec_at = std::chrono::system_clock::now() + std::chrono::seconds(_cur->seconds);
                                insert_task(_cur);
                            }
                            else {
                                delete _cur;
                            }
                        }
                    }
                }

            }
        }
    });
}

void RCON::kick_all() {
    {
        std::lock_guard<std::mutex> lock(player_mutex);
        for (auto& _x : players) {
            send_command("kick " + _x.second.number + " Auto Kick!");
        }
    }
}

void RCON::set_whitelist_enabled(bool _state) {
    whitelist_settings.enable = _state;
}

void RCON::set_white_list(const std::vector<std::string>& _guids) {
    std::lock_guard<std::mutex> lock(whitelist_settings.whitelist_mutex);
    whitelist_settings.whitelisted_guids = std::unordered_set<std::string>(_guids.begin(),_guids.end());
}

void RCON::set_open_slots(int _slots) {
    whitelist_settings.open_slots = _slots;
}

void RCON::set_white_list_kick_message(const std::string& _msg) {
    whitelist_settings.kick_message = _msg;
}

void RCON::add_to_whitelist(const std::string& _guid) {
    std::lock_guard<std::mutex> lock(whitelist_settings.whitelist_mutex);
    whitelist_settings.whitelisted_guids.insert(_guid);
}

void RCON::remove_from_whitelist(const std::string& _guid) {
    std::lock_guard<std::mutex> lock(whitelist_settings.whitelist_mutex);
    
    whitelist_settings.whitelisted_guids.erase(_guid);
}

std::vector<PlayerInfo> RCON::get_players() {
    std::lock_guard<std::mutex> lock(player_mutex);

    std::vector<PlayerInfo> _players;

    _players.reserve(players.size());
    for (auto& _x : players) {
        _players.emplace_back(_x.second);
    }
    return _players;
}

void RCON::handle_disconnect() {

    loggedin = false;

}

void RCON::bind() {
    socket->bind_receive(
        [this](const std::string& received, size_t bytes_received) {
            handle_rec(received, bytes_received);
        }
    );
    connect();
}

bool RCON::is_logged_in() {
    return loggedin;
}

RCON::~RCON(void) {
	
    send_heart_beat = false;
    run_thread = false;

    if (worker.joinable()) {
        worker.join();
    }

    delete socket;

}

void RCON::connect() {
	
	// Login Packet
	Packet rcon_packet;
	rcon_packet.command = password;
	rcon_packet.type = RCON::message_type::LOGIN;
	send_packet(rcon_packet);
	
#ifdef TEST_APP
    std::cout << "Login Packet sent" << std::endl;
#endif
}

void RCON::handle_rec(const std::string& msg, std::size_t bytes_received) {
	
#ifdef TEST_APP
    std::cout << msg << std::endl;
#endif
    
    if (msg.size() >= 8) {
		switch (msg[7]) {
			case RCON::message_type::SERVER:{
				server_response(msg);
				break;
			}
			case RCON::message_type::CHAT:{
				chat_message(msg);
				break;
			}
            case RCON::message_type::LOGIN:{
				login_response(msg);
				break;
			}
			default : {
#ifdef TEST_APP
                std::cout << "Unknown response type" << std::endl;
#endif
			}
		};
	} else {
		
#ifdef TEST_APP
        std::cout << "Malformed Message" << std::endl;
#endif
	}
}

void RCON::send_packet(const Packet& rcon_packet) {

    std::string cmd = make_be_message(rcon_packet.command,rcon_packet.type);

    socket->send(cmd, 

    //handle sent
    [this](int _bytes) {
        handle_sent(_bytes);
    });
	
}

void RCON::send_packet(const Packet& rcon_packet, std::function<void(int)> _handle_sent) {

    std::string cmd = make_be_message(rcon_packet.command, rcon_packet.type);

    if (_handle_sent) {
        socket->send(cmd, _handle_sent);
    }
    else {

        socket->send(cmd,
            //handle sent
            [this](int _bytes) {
                handle_sent(_bytes);
            }
        );

    };

}

std::string RCON::make_be_message(const std::string& cmd, const message_type& _type) {

    std::string comand = {
        static_cast<char>(0xFFu),
        static_cast<char>(_type)
    };

    switch (_type) {
        case (RCON::message_type::SERVER): {
            comand += static_cast<char>(0x00);
            comand += cmd;
            current_seq_num = ++current_seq_num % 127;
            break;
        }
        case (RCON::message_type::CHAT): {
            comand += cmd[0];
            break;
        }
        case (RCON::message_type::LOGIN): {
            comand += cmd;
            break;
        }
    }
        
    auto _crc = CRC::Calculate(comand.data(), comand.size(), CRC::CRC_32());

    std::string packet = { 'B','E',

        static_cast<char>((_crc & 0x000000FF)),
        static_cast<char>((_crc & 0x0000FF00) >> 8),
        static_cast<char>((_crc & 0x00FF0000) >> 16),
        static_cast<char>((_crc & 0xFF000000) >> 24)

    };
    packet += comand;

    return packet;

}

void RCON::handle_sent(int _bytes_sent) {
	if (_bytes_sent < 0) {
#ifdef TEST_APP
        std::cout << "Handle sent error" << std::endl;
#endif
	}
}

void RCON::login_response(const std::string& _response) {

	if (_response[8] == 0x01) {

#ifdef TEST_APP
        std::cout << "Login succeeded!" << std::endl;
#endif

		loggedin = true;

		refresh_players();
	}
	else {
		loggedin = false;
#ifdef TEST_APP
        std::cout << "Login failed!" << std::endl;
#endif
	}

}

void RCON::server_response(const std::string& msg) {

    //7bit header + 1 msg type + 1 seq num
    //payload can be nothing, command or extraheader + command
    
    //nothing, just pure ACK for seq num
    if (msg.size() <= 9) {
#ifdef TEST_APP
        std::cout << "Server ACK!" << std::endl;
#endif
        last_ACK = std::chrono::system_clock::now();
        return;
    }

	//ACK seq num
	unsigned char seq_num = msg[8];

    //extra header
    //0x00 | number of packets for this response | 0 - based index of the current packet
    bool extra_header = msg[9] == 0x00 && msg.size() > 9;   //the second part is just to make sure 

    //general
    //0x01 | received 1-byte sequence number | (possible header and/or response (ASCII string without null-terminator) OR nothing)


	if (!extra_header) {
		std::string result = msg.substr(9);
		process_message(seq_num, result);
	}
	else {
		
        //parse extra header
		unsigned char packets = msg[10];
		unsigned char packet = msg[11];

        std::string payload;
        if (msg.size() > 12) {
            payload = msg.substr(12);
        }

        bool _all_received = false;
        {
            std::lock_guard<std::mutex> lock(msg_cache_mutex);

            //          current num        parts
            std::pair< unsigned char, std::vector<std::string> > _cache;
            try {
                _cache = msg_cache.at(seq_num);
            }
            catch (std::out_of_range e) {
                _cache = {
                    0,
                    std::vector<std::string>(packets, "")
                };
            }

            if (_cache.second.size() != packets || _cache.second.size() == _cache.first) {
                //overwrite old entry
                _cache = {
                    0,
                    std::vector<std::string>(packets, "")
                };
            }

            _cache.first++;
            _cache.second[packet] = payload;

            if (_cache.first == packets) {
                _all_received = true;

                //rebuild msg
                payload.clear();
                for (auto& _part : _cache.second) {
                    payload += _part;
                }

                //we could erase the entry from the map here but.. well.. could cause rehash which takes longer

            }
            else {
                msg_cache.insert_or_assign(seq_num, _cache);
            }
        }

        if (_all_received) {
            process_message(seq_num, payload);
        }
	}
}

void RCON::chat_message(const std::string& msg) {
	
	// Respond to Server Msgs i.e chat messages, to prevent timeout
	Packet rcon_packet;
	rcon_packet.type = RCON::message_type::CHAT;
	rcon_packet.command = msg[8];
	send_packet(rcon_packet);

    // Received Chat Messages
    std::string result = msg.substr(9);
	
#ifdef TEST_APP
    std::cout << result << std::endl;
#endif

    //algorithm::trim(result);
	if (utils::starts_with(result, "Player #")) {

		if (utils::ends_with(result, " connected")) {
            result = result.substr(8);
            
            auto _space = result.find(" ");
            std::string player_number = result.substr(0, _space);
            
            auto _ip_bracket = result.find_last_of("(");
            std::string player_name = result.substr(_space + 1, _ip_bracket - (_space + 2));

            auto _ip_end = result.find(":");
            std::string ip = result.substr(_ip_bracket + 1, _ip_end - _ip_bracket - 1);
            int port = std::stoi(result.substr(_ip_end + 1, result.find(")", _ip_end) - (_ip_end + 1)));

            on_player_connect(player_number, player_name, ip, port);

		}
		else if (utils::ends_with(result, "disconnected")) {
			
            auto found = result.find(" ");
            std::string player_number = result.substr(0, found);

            auto found2 = result.find_last_of("(");
            std::string player_name = result.substr(found + 1, found2 - (found + 1));
            
            on_player_disconnect(player_number, player_name);
		}
	}
	else if (utils::starts_with(result, "Verified GUID")) {
		
        auto pos_1 = result.find("(");
		auto pos_2 = result.find(")", pos_1);

		std::string player_guid = result.substr((pos_1 + 1), (pos_2 - (pos_1 + 1)));

		pos_1 = result.find("#");
		pos_2 = result.find(" ", pos_1);
		std::string player_number = result.substr((pos_1 + 1), (pos_2 - (pos_1 + 1)));
		std::string player_name = result.substr(pos_2);

        on_player_verified_guid(player_number, player_name, player_guid);

	}
}

void RCON::on_player_connect(const std::string& _player_number, const std::string& _player_name, const std::string& _ip, int _port) {

    //increase player count
    whitelist_settings.current_players++;

    bool _kick = is_bad_player_string(_player_name);
    if (_kick) {
        send_command("kick " + _player_number + " Bad Playername! Only A-Z,a-z,0-9 allowed!");
    }
    else {
        {
            std::lock_guard<std::mutex> lock(player_mutex);
            PlayerInfo _info;
            try {
                _info = players.at(_player_name);
            }
            catch (std::out_of_range& e) {
                _info.player_name = _player_name;
            }
            _info.number = _player_number;
            _info.ip = _ip;
            _info.port = _port;
            players.insert_or_assign(_player_name, _info);
        }
        if (vpn.enable) {
            std::lock_guard<std::mutex> lock(ip_check_tasks_mutex);
            ip_check_tasks.push(_player_name);
        }
    }

}

void RCON::on_player_disconnect(const std::string& _player_number, const std::string& _player_name) {
    
    //increase player count
    whitelist_settings.current_players--;
    {
        std::lock_guard<std::mutex> lock(player_mutex);
        players.erase(_player_name);
    }

}

void RCON::on_player_verified_guid(const std::string& _player_number, const std::string& _player_name, const std::string& _player_guid) {
    
    bool _kick = whitelist_settings.enable && !is_whitelisted_player(_player_guid);
    if (_kick) {
        send_command("kick " + _player_number + " " + whitelist_settings.kick_message); 
    }
    else {
        
        std::lock_guard<std::mutex> lock(player_mutex);
        PlayerInfo _info;
        try {
            _info = players.at(_player_name);
            _info.guid = _player_guid;
            _info.verified = true;
        }
        catch (std::out_of_range& e) {
            _info.number = _player_number;
            _info.player_name = _player_name;
            _info.guid = _player_guid;
            _info.verified = true;
        }
        players.insert_or_assign(_player_name, _info);

    }
}

void RCON::send_command(const std::string& command) {

	Packet rcon_packet;
	rcon_packet.command = remove_null_terminator(command);
	rcon_packet.type = RCON::message_type::SERVER;

	send_packet(rcon_packet);
	
}

void RCON::remove_ban(const std::string& uid) {
    
    Packet rcon_packet;
    rcon_packet.command = remove_null_terminator("removeBan " + uid);
    rcon_packet.type = RCON::message_type::SERVER;

    send_packet(rcon_packet, [this](int) {
        send_packet({ remove_null_terminator("writeBans"), RCON::message_type::SERVER },
            [this](int) {
                send_command("loadBans");
            }
        );
    });
}

void RCON::add_ban(const std::string& uid) {
	
    Packet rcon_packet;
	rcon_packet.command = remove_null_terminator("addBan " + uid);
	rcon_packet.type = RCON::message_type::SERVER;

    send_packet(rcon_packet, [this](int) {
        send_packet({ remove_null_terminator("writeBans"), RCON::message_type::SERVER },
            [this](int) {
                send_command("loadBans");
            }
        );
    });
}

void RCON::refresh_players() {

    send_command("players");

}

void RCON::process_message(unsigned char sequence_number, const std::string& message) {

    std::vector<std::string> tokens = utils::split(message, '\n');

    if (tokens.size() > 0) {
        if (tokens[0] == "Missions on server:") {
            process_message_missions(tokens);
        }
        else if (tokens[0] == "Players on server:") {
            process_message_players(tokens);
        }
        else if (tokens[0] == "GUID Bans:") {
            process_message_bans(tokens);
        }
        else {
#ifdef TEST_APP
            std::cout << "Unknown message to process" << std::endl;
#endif
        }
    }
    else {
#ifdef TEST_APP
        std::cout << "Zero Split!" << std::endl << message << std::endl;
#endif
    }

}

void RCON::process_message_players(const std::vector<std::string>& tokens) {

    //players on server:
    //table header
    //-------
    //player1
    //...
    //playerN
    //..total of XX players..

    for (size_t i = 3; i < (tokens.size() - 1); ++i) {

        std::string player_str  = tokens[i];
        
        auto _nr_end = player_str.find(" ");
        auto _ip_start = player_str.find_first_not_of(" ", _nr_end);
        auto _port_delim = player_str.find(":");
        auto _port_end = player_str.find(" ", _port_delim);
        auto _ping = player_str.find_first_not_of(" ",_port_end);
        auto _ping_end = player_str.find(" ", _ping);
        auto _guid = player_str.find_first_not_of(" ", _ping_end);
        auto _guid_end = player_str.find(" ", _guid);
        auto _name = player_str.find_first_not_of(" ", _guid_end);

        //check bad layout
        if (_ip_start == std::string::npos || _port_delim == std::string::npos || _ping == std::string::npos || _guid == std::string::npos || _name == std::string::npos) {
            continue;
        }


        PlayerInfo _info;
        _info.number = player_str.substr(0, _nr_end);
        _info.ip = player_str.substr(_ip_start, _port_delim - _ip_start);
        _info.port = std::stoi(player_str.substr(_port_delim + 1, _port_end - (_port_delim + 1)));
        _info.ping = std::stoi(player_str.substr(_ping, _ping_end - _ping));
        _info.guid = player_str.substr(_guid, _guid_end - _guid);
        _info.player_name = player_str.substr(_name);
        
        auto _veri_bracket = _info.guid.find("(");
        if (_veri_bracket != std::string::npos) {
            auto _veri_str = _info.guid.substr(_veri_bracket);
            if (_veri_str == "(OK)") {
                _info.verified = true;
            }
            _info.guid = _info.guid.substr(0, _veri_bracket);
        }

        //GET lobby
        _info.lobby = false;
        if (_info.player_name.find(" (Lobby)") != std::string::npos) {
            _info.player_name = _info.player_name.substr(0, _info.player_name.size() - 8);
            _info.lobby = true;
        }

        //increase player count
        whitelist_settings.current_players++;

        //check name
        bool kick = is_bad_player_string(_info.player_name);
        if (kick) {
            send_command("kick " + _info.number + " Bad Playername!");
            continue;
        }

        //check whitelist
        if (_info.verified && whitelist_settings.enable) {
            
            if (!is_whitelisted_player(_info.guid)) {
                send_command("kick " + _info.number + " " + whitelist_settings.kick_message);
                continue;
            }
        }


        //insert into lookup
        {
            std::lock_guard<std::mutex> lock(player_mutex);
            players.insert_or_assign(_info.player_name, _info);
        }


        //issue iplookup if needed
        if (vpn.enable) {
            std::lock_guard<std::mutex> lock(ip_check_tasks_mutex);
            ip_check_tasks.push(_info.player_name);
        }
            
    }
}

void RCON::check_ip(const std::string& _player_name) {
    
    if (vpn.enable) {
        PlayerInfo _info; 
    
        {
            std::lock_guard<std::mutex> lock(player_mutex);
            try {
                _info = players.at(_player_name);
            }
            catch (std::out_of_range& e) {
                return;
            }
        }
    
        if (!is_vpn_whitelisted_player(_info.guid)) {

            auto _cache_entry = check_ip_cache(_info.ip);
            if (_cache_entry) {

                if (_cache_entry->block == 0) {
                    //residential -- ok
                    _info.country = _cache_entry->country;
                    _info.country_code = _cache_entry->country_code;
                    _info.isp = _cache_entry->isp;
                }
                else if (_cache_entry->block == 1) {
                    //proxy
                    send_command("kick " + _info.number + " " + vpn.kick_message);
                }
                else {
                    //not sure --> suspescious
                    if (vpn.kick_if_suspecious) {
                        send_command("kick " + _info.number + " " + vpn.kick_message);
                    }
                    else {
                        _info.country = _cache_entry->country;
                        _info.country_code = _cache_entry->country_code;
                        _info.isp = _cache_entry->isp;
                    }
                }

            }
            else {

                ip_counter_this_minute--;
                std::string _result;

#ifdef _REST_STANDALONE_COMPILE
                Rest_Client rclient;

                _result = rclient.request_sync("http://v2.api.iphub.info/ip/" + _info.ip);
#else 
                _result = rest->request_sync("http://v2.api.iphub.info/ip/" + _info.ip);
#endif
                /*
                auto request = std::make_shared< restbed::Request >(
                    restbed::Uri("http://v2.api.iphub.info/ip/" + _info.ip)
                    );
                */
                //request->set_header("Accept", "*/*");
                /*
                request->set_header("X-Key", vpn.api_key);

                auto response = restbed::Http::sync(request);

                if (response->get_status_code() == restbed::OK) {

                    auto length = response->get_header("Content-Length", 0);

                    restbed::Http::fetch(length, response);
                    auto _body_data = response->get_body();

                    _result.reserve(length);
                    for (auto& _x : _body_data) {
                        _result += _x;
                    }
                };
                */

                if (!_result.empty()) {
                    /*
                    {
                    "ip": "8.8.8.8",
                    "countryCode": "US",
                    "countryName": "United States",
                    "asn": 15169,
                    "isp": "GOOGLE - Google Inc.",
                    "block": 1
                    }
                    */

                    auto j = nlohmann::json::parse(_result);

                    auto _ip_info = IPInfo(
                        j["isp"].get<std::string>(),
                        j["countryName"].get<std::string>(),
                        j["countryCode"].get<std::string>(),
                        j["block"].get<int>()
                    );

                    {
                        std::lock_guard<std::mutex> lock(vpn.mutex);
                        vpn._ip_cache.insert_or_assign(_info.ip, _ip_info);
                    }

                    if (_ip_info.block == 0) {
                        //residential -- ok
                        _info.country = _ip_info.country;
                        _info.country_code = _ip_info.country_code;
                        _info.isp = _ip_info.isp;
                    }
                    else if (_ip_info.block == 1) {
                        //proxy
                        send_command("kick " + _info.number + " " + vpn.kick_message);
                    }
                    else {
                        //not sure --> suspescious
                        if (vpn.kick_if_suspecious) {
                            send_command("kick " + _info.number + " " + vpn.kick_message);
                        }
                        else {
                            _info.country = _ip_info.country;
                            _info.country_code = _ip_info.country_code;
                            _info.isp = _ip_info.isp;
                        }
                    }

                }
            }
        }
    }
}

void RCON::process_message_missions(const std::vector<std::string>& tokens) {

    std::vector<std::string> mission_names;
    for (size_t _i = 1; _i < tokens.size(); _i++) {
        auto& _x = tokens[_i];
        if (utils::ends_with(_x, ".pbo")) {
            mission_names.emplace_back(_x.substr(0, _x.size() - 4));
        }
        else {
            mission_names.emplace_back(_x);
        }
    }
    
#ifdef TEST_APP
    std::cout << "Missions: " << std::endl;
    for (auto& _x : mission_names) {
        std::cout << _x << std::endl;
    }
#endif // TEST_APP

}

void RCON::process_message_bans(const std::vector<std::string>& tokens) {

    /*
    GUID Bans:
    [#] [GUID] [Minutes left] [Reason]
    ----------------------------------------
    ...
    
    IP Bans:
    [#] [IP Address] [Minutes left] [Reason]
    ----------------------------------------------
    ...
    */

    bool _mode = false;
    for (auto& _x : tokens) {
        if (_x.size() == 0 || _x[0] == '-' || _x[0] == '[' || _x == "GUID Bans:") {
            //ignore
        }
        else if (_x == "IP Bans:") {
            _mode = true;
        }
        else {
            if (!_mode) {
                auto _guid_start = _x.find_first_not_of(" ",(_x.find(" ")));
                auto _length_start = _x.find_first_not_of(" ", (_x.find(" ",_guid_start)));
                auto _reason_start = _x.find_first_not_of(" ", (_x.find(" ",_length_start)));

                auto _guid = _x.substr(_guid_start, _length_start - _guid_start);
                auto _length = _x.substr(_length_start, _reason_start - _length_start);
                auto _reason = _x.substr(_reason_start);

#ifdef TEST_APP
                std::cout << "Ban: " << _guid << " Duration: " << _length << " Reason: " << _reason << std::endl;
#endif // TEST_APP

            }
            else {
                auto _guid_start = _x.find_first_not_of(" ", (_x.find(" ")));
                auto _length_start = _x.find_first_not_of(" ", (_x.find(" ", _guid_start)));
                auto _reason_start = _x.find_first_not_of(" ", (_x.find(" ", _length_start)));

                auto _ip = _x.substr(_guid_start, _length_start - _guid_start);
                auto _length = _x.substr(_length_start, _reason_start - _length_start);
                auto _reason = _x.substr(_reason_start);

#ifdef TEST_APP
                std::cout << "Ban: " << _ip << " Duration: " << _length << " Reason: " << _reason << std::endl;
#endif // TEST_APP
            }
        }
    }

}


bool RCON::is_bad_player_string(const std::string& player_name) {

    for (int i = 0; i < player_name.length(); i++) {
        char letter = player_name.at(i);
        bool isNumber = letter >= '0' && letter <= '9';
        bool isLetter = isNumber || (letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z');
        bool isBracket = isLetter || letter == '[' || letter == ']' || letter == ' ';
        if (!isBracket) {
            return true;
        }
    }
    return false;
}

bool RCON::is_whitelisted_player(const std::string& player_guid) {

    if (!whitelist_settings.enable) return true;

    if (whitelist_settings.current_players > whitelist_settings.open_slots) {
        std::lock_guard<std::mutex> lock(whitelist_settings.whitelist_mutex);
        return whitelist_settings.whitelisted_guids.count(player_guid) > 0;
    }
    else {
        return true;
    }

    
}

bool RCON::is_vpn_whitelisted_player(const std::string& player_guid) {

    std::lock_guard<std::mutex> lock(vpn.mutex);
    return vpn.exception_guids.count(player_guid) > 0;

}

std::optional<RCON::IPInfo> RCON::check_ip_cache(const std::string& _ip) {

    std::lock_guard<std::mutex> lock(vpn.mutex);
    try {
        return vpn._ip_cache.at(_ip);
    }
    catch (std::out_of_range& e) {
        return std::nullopt;
    }

}


void RCON::add_task(const TaskType& _type, const std::string& _data, bool _repeat, int _seconds) {

    auto _new_task = new Task();
    _new_task->data = _data;
    _new_task->type = _type;
    _new_task->repeat = _repeat;
    _new_task->seconds = _seconds;
    _new_task->exec_at = std::chrono::system_clock::now() + std::chrono::seconds(_seconds);

    insert_task(_new_task);
}

void RCON::insert_task(Task * _new_task) {

    {
        std::lock_guard<std::mutex> lock(task_mutex);

        Task * _cur = task_head;
        Task * _before = nullptr;

        while (_cur != nullptr) {
            if (_cur->exec_at >= _new_task->exec_at) {
                _before->next_task = _new_task;
                _new_task->next_task = _cur;
                break;
            }
            _before = _cur;
            _cur = _cur->next_task;
        }

        if (_cur == nullptr) {
            if (_before != nullptr) {
                _before->next_task = _new_task;
            }
            else {
                task_head = _new_task;
            }
        }
    }

}

void RCON::enable_auto_reconnect() {
    auto_reconnect = true;
}

void RCON::enable_vpn_detection() {
    vpn.enable = true;
}

void RCON::set_vpn_detect_kick_msg(const std::string& _msg) {
    vpn.kick_message = _msg;
}

void RCON::set_iphub_api_key(const std::string& _msg) {
    vpn.api_key = _msg;
}

void RCON::add_vpn_detection_guid_exception(const std::string& _guid) {
    std::lock_guard<std::mutex> lock(vpn.mutex);
    vpn.exception_guids.insert(_guid);
}

void RCON::enable_vpn_suspecious_kicks() {
    vpn.kick_if_suspecious = true;
}

void RCON::set_max_players(int _players) {
    whitelist_settings.max_players = _players;
}

#ifndef _REST_STANDALONE_COMPILE
void RCON::set_rest_api(rest_api * _rest) {
    rest = _rest;
}
#endif
