#include <thread>
#include <iostream>
#include <array>
#include <mutex>
#include <atomic>


#include <asio.hpp>


using asio::ip::udp;
using asio::ip::address;

class UDP_Socket {

    bool connected = false;

    std::mutex mtx;

    //general
    std::string ip;
    int port;

    bool auto_reconnect = true;
    int maximum_reconnects = 5;

    //sending & receiving
    asio::io_service io_service;
    udp::endpoint remote_endpoint;
    udp::socket socket;

    //io thread
    std::thread run_thread;

    //callback
    std::function<void(const std::string& received, size_t bytes_received)> handle_receive_func;
    
    std::function<void()> disconnected_func;

    void disconnected() {
        
        bool _connected = connected;
        {
            std::lock_guard<std::mutex> lock(mtx);
            connected = false;
            socket.close();
        }

        if (disconnected_func && _connected) {
            disconnected_func();
        }
    }

    void handle_sent(std::shared_ptr<std::string> _message, const std::function<void(int)>& _func, const asio::error_code& error, const std::size_t& bytes_trasferred) {

        if (error) {

            disconnected();
            if (_func) {
                _func(-1);
            }

        }
        else {

            if (_func) {
                _func(bytes_trasferred);
            }
        }


    }

    void handle_receive(std::shared_ptr<std::string> _buffer, const asio::error_code& error, size_t bytes_transferred) {

        if (!error) {

            std::string message((*_buffer).begin(), (*_buffer).begin() + bytes_transferred);

            if (handle_receive_func) {
                handle_receive_func(message, bytes_transferred);
            }
            bind();

        }
        else {

            disconnected();

        }

    }

    void bind() {
        
        std::shared_ptr<std::string> _buffer = std::make_shared<std::string>(2048, 0);
        
        std::lock_guard<std::mutex> lock(mtx);
        socket.async_receive(
            asio::buffer(_buffer->data(), _buffer->size()),
            std::bind(
                &UDP_Socket::handle_receive, this, _buffer,
                std::placeholders::_1,  //error
                std::placeholders::_2   //bytes transferred
            )
        );
    }
public:

    bool is_connected() {
        return connected;
    }

    UDP_Socket(const std::string& _ip, int _port, std::function<void()> _disconnect_cb) : 
        socket(io_service),
        ip(_ip),
        port(_port),
        disconnected_func(_disconnect_cb)
    {

        remote_endpoint = udp::endpoint(address::from_string(ip), port);
        
        asio::error_code _error;
        socket.connect(remote_endpoint, _error);

        if (!_error) {
            connected = true;
            std::thread([this]() {
           
                try {
                    asio::io_service::work work(io_service);
                    io_service.run();
                }
                catch (std::exception& e) {
                    //bp here
                }
            }).detach();
        }
        else {
            connected = false;
            //TODO try reconnect
        }



    }

    bool reconnect() {
        
        asio::error_code error;
        {
            std::lock_guard<std::mutex> lock(mtx);
            remote_endpoint = udp::endpoint(asio::ip::address::from_string(ip), port);
            socket.connect(remote_endpoint, error);
        }

        if (error) {
            disconnected();
        }
        return !error;
    }

    ~UDP_Socket() {

        io_service.stop();
        socket.close();
        
    }

    void send(const std::string& message, const std::function<void(int)> _fnc) {
        
        std::shared_ptr<std::string> _message_pers = std::make_shared<std::string>(message);

        {
            std::lock_guard<std::mutex> lock(mtx);
            socket.async_send(
                asio::buffer(*_message_pers),
                std::bind(
                    &UDP_Socket::handle_sent, this, _message_pers, _fnc,
                    std::placeholders::_1,  //error
                    std::placeholders::_2   //bytes transferred
                )
            );
        }

    }

    void bind_receive(const std::function<void(const std::string& received, size_t bytes_received)>& _fnc) {

        handle_receive_func = _fnc;

        bind();
    }

};
