#ifndef MY_WIFI_H_
#define MY_WIFI_H_

#include <string>
#include <functional>
#include "esp_timer.h"
#include "esp_wifi.h"
#include "my_storage.h"
#include "AsyncWebServer.h"

#define CONFIG_SSID_LEN     32
#define CONFIG_PASSWD_LEN   63

class MyWifi {
public:
    static MyWifi& GetInstance() {
        static MyWifi instance;
        return instance;
    }
    void    Start();
    void    Stop();
    bool    IsConnected();
    uint8_t GetChannel();
    int8_t  GetRssi();
    bool    WaitForConnected(int timeout_ms = 5000);
    void    EnterConfigMode();
    const std::string& GetSsid() const { return ssid_; }
    const std::string& GetIpAddress() const { return ip_address_; }
    bool    SaveAuth(const std::string& ssid, const std::string& passwd);
    void    SetApSsid(const std::string&& prefix);

    void SetPowerSaveMode(bool enabled) {
        ESP_ERROR_CHECK(esp_wifi_set_ps(enabled ? WIFI_PS_MIN_MODEM : WIFI_PS_NONE));
    }
    void OnConnect(std::function<void(const std::string& ssid)> on_connect) {
        on_connect_ = on_connect;
    }
    void OnConnected(std::function<void(const std::string& ssid)> on_connected) {
        on_connected_ = on_connected;
    }
    void OnScanBegin(std::function<void()> on_scan_begin) {
        on_scan_begin_ = on_scan_begin;
    }

private:
    struct WifiRecord {
        uint8_t             ssid[CONFIG_SSID_LEN + 1];      // 网络名称
        uint8_t             passwd[CONFIG_PASSWD_LEN + 1];  // 网络密码
        uint8_t             channel;                        // 网络通道
        wifi_auth_mode_t    authmode;                       // 网络认证模式
        uint8_t             bssid[6];                       // 网络物理地址
    };
    struct WifiAuth {
        char    ssid[CONFIG_SSID_LEN + 1];
        char    passwd[CONFIG_PASSWD_LEN + 1];
    };

    MyWifi();
    ~MyWifi();

    // 显式删除复制构造函数、赋值操作符
    MyWifi(const MyWifi&) = delete;
    MyWifi& operator=(const MyWifi&) = delete;

    void StartAccessPoint();
    static void IndexHandle(AsyncWebServerRequest* req);
    bool ConnectTo(const std::string& ssid, const std::string& passwd, bool block=true);
    void StartWebServer();
    void HandleScanResult();
    void HandleDisconnected();
    void StartConnect();
    static void WifiEventHandler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data);
    static void IpEventHandler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data);

    std::string     ssid_;
    std::string     password_;
    std::string     ip_address_;
    std::string     language_;
    std::string     json_;
    std::string     ap_ssid_;

    int8_t          max_tx_power_ = 0;
    uint8_t         remember_bssid_;
    uint8_t         reconnect_count_ = 0;
    bool            sleep_mode_;
    bool            config_mode_ = false;
    bool            is_connecting_ = false;
    std::string     ota_url_;
    std::string     default_ssid_;

    EventGroupHandle_t  event_group_{nullptr};
    esp_netif_t*        station_if_{nullptr};
    esp_netif_t*        ap_if_{nullptr};
    esp_timer_handle_t  timer_handle_{nullptr};
    AsyncWebServer*     server_{nullptr};


    esp_event_handler_instance_t instance_any_id_ = nullptr;
    esp_event_handler_instance_t instance_got_ip_ = nullptr;

    
    MyStorage<WifiAuth>             storage_;
    std::vector<WifiRecord>         connect_queue_;     // 应当在用完后销毁
    std::vector<wifi_ap_record_t>   scan_result_;       // 应当在用完后销毁

    std::function<void(const std::string& ssid)>    on_connect_;
    std::function<void(const std::string& ssid)>    on_connected_;
    std::function<void()>                           on_scan_begin_;

};

#endif // !MY_WIFI_H_