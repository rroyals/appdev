#include <iostream>
#include <vector>
#include <string_view>
#include <string>
#include <memory>

#define __forceinline __attribute__((always_inline))

#pragma region "ssl"

class c_ssl {
    private:
        std::string_view m_cert, m_key, m_ca;
        std::string m_passphrase;

    public:

        WOLFSSL_CTX* m_ctx;

        c_ssl(const std::string_view cert, const std::string_view key,
            const std::string_view ca = "")
            : m_cert{cert}, m_key{key}, m_ca{ca}, m_ctx{nullptr} {
            wolfSSL_library_init();
            }
            ~c_ssl() = default;

        bool init() {
            m_ctx = wolfSSL_CTX_new(wolfTLS_server_method());
            if (!m_ctx) {
            printf("failed to create ssl context\n");
            return false;
            }

            wolfSSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, 0);
            int res = wolfSSL_CTX_use_certificate_chain_file(m_ctx, m_cert.data());
            if (res != 1) {
            printf("failed to load cert\n");
            return false;
            }

            //wolfSSL_CTX_set_default_passwd_cb_userdata(m_ctx, m_passphrase.data());

            res = wolfSSL_CTX_use_PrivateKey_file(m_ctx, m_key.data(), SSL_FILETYPE_PEM);
            if (res != 1) {
            printf("failed to load private key\n");
            return false;
            }

            res = wolfSSL_CTX_check_private_key(m_ctx);
            if (res != 1) {
            printf("failed to verify private key\n");
            return false;
            }

            res = wolfSSL_CTX_load_verify_locations(m_ctx, m_ca.data(), nullptr);
            if (res != 1) {
            printf("failed to load root ca\n");
            return false;
            }

            return true;
        }

        auto& get_context() { return m_ctx; }
};

#pragma endregion

#pragma region "client"

class i_client {
    public:
        static size_t pos; //need to test more
        i_client() = default;
        virtual ~i_client() = default;


};

class c_client : public i_client {
    public:
        struct client_t {
            int socket_id;
            int last_check;
            //bool authenticated;
            //bool logged_in;
            std::string username;
            std::string ip;
            std::string hwid;
        };
        client_t info = { };

        c_client(int socket_id, int last_check, std::string username,
                 std::string ip, std::string hwid) {
                     info = {
                         socket_id,
                         last_check,
                         username,
                         ip,
                         hwid
                     };
                 }
        c_client(client_t info) {
            this->info = {
                info.socket_id,
                info.last_check,
                info.username,
                info.ip,
                info.hwid
            };
        }
        ~c_client() = default;

        
        const std::string to_string() const {
            return std::string(std::to_string(info.socket_id)  + ", " +
                               std::to_string(info.last_check) + ", " +
                               info.username                   + ", " +
                               info.ip                         + ", " +
                               info.hwid);
        }

        __forceinline void test_string_view(std::string_view string) {
            std::cout << string << "\n";
        }

        __forceinline void test_string(const std::string& string) {
            std::cout << string << "\n";
        }

    private:
        //private
};

class c_authenticated_client : public c_client {
    public:
        c_authenticated_client(const int socket_id, const int last_check, const std::string username,
                               const std::string ip, const std::string hwid)
                               : c_client { socket_id, last_check, username, ip, hwid } { }
        c_authenticated_client(client_t info)
                               : c_client { info } { }
        ~c_authenticated_client() = default;

    private:
        
};

#pragma endregion

class c_server {
    public:
        struct server_t {
            int online_clients;
            int authenticated_clients;
            std::string client_signature;
        };
        server_t info = { 
            0, //online_clients
            0, //authenticated_clients
            "" //client_signature
        };

        enum e_server_response {
            RESPONSE_SUCCESS,
            RESPONSE_FAILURE = 0x1
        };

        c_server() {
            //get client_signature
        }
        ~c_server() = default;

        bool init_socket()                                      = delete; //implement

        bool init_parent()                                      = delete; //implement

        e_server_response process_parent_request()              = delete; //implement

        inline const std::vector<std::unique_ptr<i_client>>* get_clients() const                 { return &this->online_clients_; }
        inline const std::vector<std::unique_ptr<c_authenticated_client>>* get_clients_2() const { return &this->authenticated_clients_; }

        __forceinline void add_client(c_client::client_t info) { this->online_clients_.emplace_back(std::unique_ptr<c_client>(std::make_unique<c_client>(info))); }

        __forceinline void add_client_2(c_client::client_t info) { this->online_clients_.emplace_back(std::unique_ptr<c_authenticated_client>(std::make_unique<c_authenticated_client>(info))); }

        void append_large(c_client::client_t info) {
            for (auto i = 0; i < 1000000; i++) {
                this->online_clients_.emplace_back(std::unique_ptr<c_client>(std::make_unique<c_client>(info)));
            }
        }

    private:
        int parent_socket_;
        std::vector<std::unique_ptr<i_client>> online_clients_ { };
        std::vector<std::unique_ptr<c_authenticated_client>> authenticated_clients_ { }; //for easier parsing

};

namespace g {
    std::unique_ptr<c_server> ptr_server = std::make_unique<c_server>();
}

int main() {
    auto ptr_client_list = g::ptr_server->get_clients();
    auto ptr_auth_client_list = g::ptr_server->get_clients_2();
    c_client::client_t info = {
        0,
        0,
        "test_user",
        "127.0.0.1",
        "WOUDAWY282902WIOUDOW92902"
    };

    g::ptr_server->append_large(info);
    std::cout << "client list populated, press [enter] to start\n";
    std::cin.get();
    auto t = std::chrono::high_resolution_clock::now();
    for (auto i = 0; i < 10; i++) {
        for (auto it = ptr_client_list->begin(); it != ptr_client_list->end(); ++it) {
            //dynamic ...
            //all c_client (multiple casts) -> .83 seconds/cycle per 1 million clients
            //all c_authenticated_client -> .0348 seconds/cycle per 1 million clients
            /* try {
                auto& client = dynamic_cast<c_authenticated_client&>(*(it->get()));
                //std::cout << client.info.username << "\n";
            } catch(const std::bad_cast& e) {
                auto& client = static_cast<c_client&>(*(it->get()));
                //std::cout << client.info.username << "\n";
            } */

            //static ... 
            //all c_client -> .0132 seconds/cycle per 1 million clients
            //all c_authenticated_client -> .0133 seconds/cycle per 1 million clients
            auto& client = static_cast<c_client&>(*(it->get()));
            //string_view -> .0335 seconds/cycle per 1 million clients
            /* std::string_view client_username { client.info.username.c_str(), client.info.username.size() };
            client.test_string_view(client_username); */
            //string -> fastest
            /* const std::string& client_username { client.info.username };
            client.test_string(client_username); */
        }
    }
    auto delta_t = std::chrono::high_resolution_clock::now() - t;
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(delta_t).count() << " ms\n";
    return 1337;
}