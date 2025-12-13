#include "my_wifi.h"
#include "esp_event.h"
#include "esp_wifi_default.h"
#include "esp_log.h"
#include <algorithm>
#include "esp_mac.h"
#include "lwip/ip4_addr.h"
#include "cJSON.h"

#define TAG "MyWifi"

#define WIFI_CONNECTED_BIT      BIT0
#define WIFI_FAIL_BIT           BIT1
#define SSID_VECTOR_FREE_BIT    BIT2
#define MAX_RECONNECT_COUNT     3

extern const char index_html_start[] asm("_binary_wifi_configuration_html_start");
extern const char done_html_start[] asm("_binary_wifi_configuration_done_html_start");

MyWifi::MyWifi()
    : storage_(MyStorage<WifiAuth>("Wifi", DECLARE_META(WifiAuth,
        FIELD(WifiAuth, ssid),
        FIELD(WifiAuth, passwd)
        )))
{
    event_group_ = xEventGroupCreate();
    xEventGroupSetBits(event_group_, SSID_VECTOR_FREE_BIT);

    MyNVS nvs("wifi", NVS_READONLY);
    if(ESP_OK != nvs.read("max_tx_power", max_tx_power_)) {
        max_tx_power_ = 0;
    }
    if(ESP_OK != nvs.read("remember_bssid", remember_bssid_)) {
        remember_bssid_ = 0;
    }
    if (ESP_OK != nvs.read("default_ssid", default_ssid_)) {
        default_ssid_.clear();
    }
}

MyWifi::~MyWifi()
{
    Stop();
    vEventGroupDelete(event_group_);
}

void MyWifi::Start()
{
    // 初始化协议栈
    ESP_ERROR_CHECK(esp_netif_init());

    // 注册事件处理器
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &MyWifi::WifiEventHandler,
                                                        this,
                                                        &instance_any_id_));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &MyWifi::IpEventHandler,
                                                        this,
                                                        &instance_got_ip_));

    // 配置网络接口
    station_if_ = esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    cfg.nvs_enable = false;
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    if (max_tx_power_ != 0) {
        ESP_ERROR_CHECK(esp_wifi_set_max_tx_power(max_tx_power_));
    }

    // 初始化扫描定时器
    esp_timer_create_args_t timer_args = {
        .callback = [](void* arg) {
            esp_wifi_scan_start(nullptr, false);
        },
        .arg = this,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "WiFiScanTimer",
        .skip_unhandled_events = true
    };
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &timer_handle_));
}

void MyWifi::Stop()
{
    if (timer_handle_ != nullptr) {
        esp_timer_stop(timer_handle_);
        esp_timer_delete(timer_handle_);
        timer_handle_ = nullptr;
    }
    
    // 取消注册事件处理程序
    if (instance_any_id_ != nullptr) {
        ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id_));
        instance_any_id_ = nullptr;
    }
    if (instance_got_ip_ != nullptr) {
        ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip_));
        instance_got_ip_ = nullptr;
    }

    // Reset the WiFi stack
    ESP_ERROR_CHECK(esp_wifi_stop());
    ESP_ERROR_CHECK(esp_wifi_deinit());

    if (station_if_ != nullptr) {
        esp_netif_destroy(station_if_);
        station_if_ = nullptr;
    }

}

bool MyWifi::IsConnected()
{
    return xEventGroupGetBits(event_group_) & WIFI_CONNECTED_BIT;
}

uint8_t MyWifi::GetChannel()
{
    wifi_ap_record_t ap_info;
    ESP_ERROR_CHECK(esp_wifi_sta_get_ap_info(&ap_info));
    return ap_info.primary;
}

int8_t MyWifi::GetRssi() {
    wifi_ap_record_t ap_info;
    ESP_ERROR_CHECK(esp_wifi_sta_get_ap_info(&ap_info));
    return ap_info.rssi;
}

/// @brief 等等连接结果
/// @param timeout_ms 等待时间
/// @return 连接成功返回true
bool MyWifi::WaitForConnected(int timeout_ms) {
    auto bits = xEventGroupWaitBits(event_group_, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, timeout_ms / portTICK_PERIOD_MS);
    return (bits & WIFI_CONNECTED_BIT) != 0;
}


bool MyWifi::SaveAuth(const std::string& ssid, const std::string& passwd)
{
    WifiAuth wifi;
    strcpy(wifi.ssid, ssid.c_str());
    strcpy(wifi.passwd, passwd.c_str());
    return storage_.Upsert([&wifi](const WifiAuth& auth) {
        return strcmp(auth.ssid, wifi.ssid) == 0;
    }, wifi);
}


/// @brief WiFi事件处理器
void MyWifi::WifiEventHandler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    auto* this_ = reinterpret_cast<MyWifi*>(arg);

    switch (event_id)
    {
      case WIFI_EVENT_STA_START:
        esp_wifi_scan_start(nullptr, false);
        if (this_->on_scan_begin_) {
            this_->on_scan_begin_();
        }
        break;
      case WIFI_EVENT_SCAN_DONE:
        this_->HandleScanResult();
        break;
      case WIFI_EVENT_STA_CONNECTED:
        xEventGroupSetBits(this_->event_group_, WIFI_CONNECTED_BIT);
        break;
      case WIFI_EVENT_STA_DISCONNECTED:
        this_->HandleDisconnected();
        break;
      case WIFI_EVENT_AP_STACONNECTED:
      case WIFI_EVENT_AP_STADISCONNECTED:
        auto* event = reinterpret_cast<wifi_event_ap_staconnected_t*>(event_data);
        ESP_LOGI(TAG, "Station " MACSTR " %s, AID=%d", 
                    MAC2STR(event->mac), 
                    (event_id == WIFI_EVENT_AP_STACONNECTED) ? "joined" : "left",
                    event->aid);
        break;
    }
}

/// @brief 处理扫描结束事件
void MyWifi::HandleScanResult()
{
    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    if (ap_num == 0) {
        return;
    }
    xEventGroupWaitBits(event_group_, SSID_VECTOR_FREE_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
    scan_result_.resize(ap_num);
    auto* data_ptr = scan_result_.data();
    esp_wifi_scan_get_ap_records(&ap_num, scan_result_.data());
    std::sort(data_ptr, data_ptr + ap_num, [this](const wifi_ap_record_t& a, const wifi_ap_record_t& b) {
        if (default_ssid_ == (char*)a.ssid) {
            return true;
        }
        if (default_ssid_ == (char*)b.ssid) {
            return false;
        }
        
        return a.rssi > b.rssi;
    });

    // 根据运行模式处理扫描结果
    if (config_mode_) {
        esp_timer_start_once(timer_handle_, 10 * 1000000);
    } else {
        // 获取连接列表
        if (storage_.GetUsed()) {
            storage_.ForeachReadOnly([this](const WifiAuth& auth){
                auto it = std::find_if(scan_result_.begin(), scan_result_.end(),
                    [&auth](const wifi_ap_record_t& record){
                        return strcmp(reinterpret_cast<const char*>(record.ssid), auth.ssid) == 0;
                    });
                if (it != scan_result_.end()) {
                    ESP_LOGI(TAG, "Found AP: %s, BSSID: %02x:%02x:%02x:%02x:%02x:%02x, RSSI: %d, Channel: %d, Authmode: %d",
                            (char *)it->ssid, 
                            it->bssid[0], it->bssid[1], it->bssid[2],
                            it->bssid[3], it->bssid[4], it->bssid[5],
                            it->rssi, it->primary, it->authmode);
                    WifiRecord record = {};
                    record.authmode = it->authmode;
                    record.channel = it->primary;
                    strcpy(reinterpret_cast<char*>(record.ssid), auth.ssid);
                    strcpy(reinterpret_cast<char*>(record.passwd), auth.passwd);
                    memcpy(record.bssid, it->bssid, 6);
                    connect_queue_.push_back(record);
                }
                // 遍历全部
                return false;
            });
        }

        // 开始连接/重新扫描
        if (connect_queue_.empty()) {
            ESP_LOGI(TAG, "Wait for next scan");
            esp_timer_start_once(timer_handle_, 100 * 1000);
            xEventGroupSetBits(event_group_, SSID_VECTOR_FREE_BIT);
            return;
        } else {
            StartConnect();
        }
    }
    xEventGroupSetBits(event_group_, SSID_VECTOR_FREE_BIT);
}

/// @brief 处理断开事件
void MyWifi::HandleDisconnected()
{
    xEventGroupClearBits(event_group_, WIFI_CONNECTED_BIT);

    if (config_mode_) {
        xEventGroupSetBits(event_group_, WIFI_FAIL_BIT);
    } else {
        if (reconnect_count_ < MAX_RECONNECT_COUNT) {
            esp_wifi_connect();
            reconnect_count_ ++;
            ESP_LOGI(TAG, "Reconnecting %s (attempt %d/%d)", ssid_.c_str(), reconnect_count_, MAX_RECONNECT_COUNT);
            return;
        }
        
        if (connect_queue_.size()) {
            StartConnect();
            return;
        } else {
            ESP_LOGI(TAG, "No more AP to connect, wait for next scan.");
            esp_timer_start_once(timer_handle_, 10 * 1000);
        }
    }
}


/// @brief 开始连接
void MyWifi::StartConnect()
{
    auto ap_record = connect_queue_.front();
    connect_queue_.erase(connect_queue_.begin());
    ssid_ = std::string(reinterpret_cast<char*>(ap_record.ssid));
    password_ = std::string(reinterpret_cast<char*>(ap_record.passwd));

    if (on_connect_) {
        on_connect_(ssid_);
    }

    ConnectTo(ssid_, password_, false);
}

/// @brief IP事件处理器
void MyWifi::IpEventHandler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    auto* this_ = reinterpret_cast<MyWifi*>(arg);
    auto* event = reinterpret_cast<ip_event_got_ip_t*>(event_data);

    char ip_addr[16];
    esp_ip4addr_ntoa(&event->ip_info.ip, ip_addr, sizeof(ip_addr));
    this_->ip_address_ = ip_addr;
    ESP_LOGI(TAG, "Got IP: %s", ip_addr);

    xEventGroupSetBits(this_->event_group_, WIFI_CONNECTED_BIT);
    if (this_->on_connected_) {
        this_->on_connected_(this_->ssid_);
    }
    this_->connect_queue_.clear();
    this_->connect_queue_.resize(0);
    this_->reconnect_count_ = 0;
}

/// @brief 进入配置模式
void MyWifi::EnterConfigMode() 
{
    config_mode_ = true;
    if (ap_ssid_.empty()) {
        SetApSsid("wifi");
    }
    StartAccessPoint();
    StartWebServer();
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}


/// @brief 启动AP
void MyWifi::StartAccessPoint()
{
    wifi_mode_t current_mode{};
    auto err = esp_wifi_get_mode(&current_mode);
    if (err == ESP_ERR_WIFI_NOT_INIT) {
        ESP_LOGI(TAG, "Initialize Wi-Fi ...");
        esp_netif_init();
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        cfg.nvs_enable = false;
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    } else if (err != ERR_OK) {
        ESP_LOGE(TAG, "Failed to get Wi-Fi mode, err=%s", esp_err_to_name(err));
        esp_netif_init();
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        cfg.nvs_enable = false;
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    }

    wifi_mode_t mode_after_init;
    if (esp_wifi_get_mode(&mode_after_init) == ESP_OK && mode_after_init != WIFI_MODE_NULL) {
        ESP_LOGI(TAG, "Stopping current Wi-Fi mode (%d)", mode_after_init);
        ESP_ERROR_CHECK(esp_wifi_stop());
    }

    ap_if_ = esp_netif_create_default_wifi_ap();
    esp_netif_ip_info_t ip_info;
    IP4_ADDR(&ip_info.ip, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.gw, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);
    esp_netif_dhcps_stop(ap_if_);
    esp_netif_set_ip_info(ap_if_, &ip_info);
    esp_netif_dhcps_start(ap_if_);

    // 启动DNS。。。。。。。。。。。。。。还没有想好怎么处理............使用异步TCP

    // Set the WiFi configuration
    wifi_config_t wifi_config = {};
    strcpy((char *)wifi_config.ap.ssid, ap_ssid_.c_str());
    wifi_config.ap.ssid_len = ap_ssid_.length();
    wifi_config.ap.max_connection = 4;
    wifi_config.ap.authmode = WIFI_AUTH_OPEN;

    // Start the WiFi Access Point
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Access Point started with SSID %s", ap_ssid_.c_str());

    // 读取OTA URL
    MyNVS nvs("wifi", NVS_READWRITE);
    std::string ota_url;
    if (ESP_OK == nvs.read("ota_url", ota_url)) {
        ota_url_ = ota_url;
    }
    // 读取WiFi功率
    if (ESP_OK == nvs.read("max_tx_power", max_tx_power_)) {
        ESP_LOGI(TAG, "WiFi max tx power from NVS: %d", max_tx_power_);
        ESP_ERROR_CHECK(esp_wifi_set_max_tx_power(max_tx_power_));
    } else {
        esp_wifi_get_max_tx_power(&max_tx_power_);
    }
    // 读取BSSID记忆设置
    if (ESP_OK == nvs.read("remember_bssid", remember_bssid_)) {
        remember_bssid_ = false;    // 默认值
    }
    // 读取睡眠模式设置
    if (ESP_OK == nvs.read("sleep_mode", sleep_mode_)) {
        sleep_mode_ = true; // 默认值
    }
}

/// @brief 主页处理程序
void MyWifi::IndexHandle(AsyncWebServerRequest* req)
{
    req->send(200, "text/html; charset=utf-8", index_html_start);
}

/// @brief 以指定方式连接指定的WiFi
/// @return 在阻塞方式下连接成功返回true，超时10s或连接失败时返回false；非阻塞时连接完成返回true
bool MyWifi::ConnectTo(const std::string& ssid, const std::string& passwd, bool block)
{
    if (ssid.empty()) {
        ESP_LOGE(TAG, "SSID cannot be empty.");
        return false;
    }
    if (ssid.length() > 32) {
        ESP_LOGE(TAG, "SSID too long.");
        return false;
    }
    if (passwd.length() > 63) {
        ESP_LOGE(TAG, "Password too long.");
        return false;
    }

    is_connecting_ = true;
    esp_wifi_scan_stop();
    xEventGroupClearBits(event_group_, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

    wifi_config_t wifi_config;
    bzero(&wifi_config, sizeof(wifi_config));
    strcpy((char *)wifi_config.sta.ssid, ssid.c_str());
    strcpy((char *)wifi_config.sta.password, passwd.c_str());
    wifi_config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    wifi_config.sta.failure_retry_cnt = 1;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    auto error = esp_wifi_connect();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "Failed to connect to WiFi: %d", error);
        is_connecting_ = false;
        return false;
    }
    ESP_LOGI(TAG, "Connecting to WiFi %s", ssid.c_str());

    if (block) {
        auto bits = xEventGroupWaitBits(event_group_, 
                                    WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, 
                                    pdTRUE, 
                                    pdFALSE,
                                    pdMS_TO_TICKS(10000));
        is_connecting_ = false;
        if (bits & WIFI_FAIL_BIT) {
            ESP_LOGE(TAG, "Failed to connect to WiFi %s", ssid.c_str());
            return false;
        }
        ESP_LOGI(TAG, "Connected to WiFi %s", ssid.c_str());
    }

    return true;
}

/// @brief 启动Web服务器
void MyWifi::StartWebServer()
{
    server_ = new AsyncWebServer(80);
    server_->on("/", IndexHandle);
    server_->on("/index.html", IndexHandle);
    server_->on("/done.html", [this](AsyncWebServerRequest* req) {
        req->send(200, "text/html; charset=utf-8", done_html_start);
    });
    server_->on("/saved/list", [this](AsyncWebServerRequest* req) {
        std::string json = R"([)";
        if (!default_ssid_.empty()) {
            json += R"(")" + default_ssid_ + R"(",)";
        }
        storage_.ForeachReadOnly([this, &json](const WifiAuth& wifi) {
            if (default_ssid_ != wifi.ssid) {
                json += R"(")" + std::string(wifi.ssid) + R"(",)";            
            }
            return false;
        });
        if (json.length() > 1) {
            json.pop_back();
        }
        json += R"(])";
        req->send(200, "application/json", json);
    });
    server_->on("/saved/set_default", [this](AsyncWebServerRequest* req) {
        default_ssid_ = req->arg("ssid");
        MyNVS nvs("wifi", NVS_READWRITE);
        auto err = nvs.write("default_ssid", default_ssid_);
        if (err == ESP_OK) {
            req->send(200, "application/json", R"({"success":true})");
        } else {
            req->send(500, "application/json", R"({"success":false})");
        }
    });
    server_->on("/saved/delete", [this](AsyncWebServerRequest* req) {
        std::string ssid = req->arg("ssid");
        if (ssid == default_ssid_) {
            default_ssid_.clear();
        }
        bool del = storage_.Del([&ssid](const WifiAuth& wifi){
            return strcmp(wifi.ssid, ssid.c_str()) == 0;
        });
        if (del) {
            req->send(200, "application/json", R"({"success":true})");
        } else {
            req->send(200, "application/json", R"({"success":false, "error":"SSID not found"})");
        }
    });
    server_->on("/scan", [this](AsyncWebServerRequest* req) {
        auto* response = req->beginChunkedResponse("application/json", [this](uint8_t* buffer, size_t maxLen, size_t index) -> size_t {
            static size_t current = 0;
            char buf[128];

            auto scan_size = scan_result_.size();
            if (current >= scan_size) {
                current = 0;
                return 0;
            }

            snprintf(buf, 128, "%s{\"ssid\":\"%s\",\"rssi\":%d,\"authmode\":%d}%s",
                                    (current == 0) ? "[" : "",
                                    (char*)scan_result_[current].ssid,
                                    scan_result_[current].rssi,
                                    scan_result_[current].authmode,
                                    current == (scan_size - 1 )? "]" : ",");
            current++;
            auto size =  strlen(buf);
            if (size <= maxLen) {
                memcpy(buffer, buf, size);
            } else {
                ESP_LOGE(TAG, "Buffer too small for AP data, need %d, available %d", size, maxLen);
                current = 0;
                size = 0;
            }
            return size;
        });

        xEventGroupWaitBits(event_group_, SSID_VECTOR_FREE_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
        req->send(response);
        xEventGroupSetBits(event_group_, SSID_VECTOR_FREE_BIT);
    });
    server_->on("/submit", HTTP_POST, 
        [](AsyncWebServerRequest *req){},
        nullptr,
        [this](AsyncWebServerRequest *req, uint8_t *data, size_t len, size_t index, size_t total) {
            if (total > 1024) {
                req->send(400, "text/plain", "Payload too large");
            }

            // 针对小的数据块进行优化
            const char* json_ptr = nullptr;
            if (len == total) {
                json_ptr = (const char*)data;
            } else {
                if (index == 0) {
                    json_.clear();
                }
                json_.append((char*)data, len);
                if (index + len == total) {
                    json_ptr = json_.c_str();
                }
            }
            
            if (json_ptr) {
                auto* json = cJSON_Parse(json_ptr);
                if (!json) {
                    req->send(400, "Invalid JSON.");
                } 

                auto* ssid = cJSON_GetObjectItemCaseSensitive(json, "ssid");
                auto* passwd = cJSON_GetObjectItemCaseSensitive(json, "password");
                if (!cJSON_IsString(ssid) || (ssid->valuestring == NULL) || (strlen(ssid->valuestring) >= 33)) {
                    req->send(200, "application/json", R"({"success":false,"error":"无效的 SSID"})");
                    cJSON_Delete(json);
                    return;
                }
                std::string ssid_str = ssid->valuestring;
                std::string passwd_str = "";
                if (cJSON_IsString(passwd) && (passwd->valuestring != NULL) && (strlen(passwd->valuestring) < 65)) {
                    passwd_str = passwd->valuestring;
                }
                
                // 尝试连接
                if (ConnectTo(ssid_str, passwd_str)) {
                    SaveAuth(ssid_str, passwd_str);
                    req->send(200, "application/json", R"({"success":true})");
                } else {
                    req->send(200, "application/json", R"({"success":false,"error":"无法连接到 WiFi"})");
                }
                cJSON_Delete(json);
            }
        }
    );
    server_->on("/reboot", [this](AsyncWebServerRequest* req) {
        req->send(200, "application/json", R"({"success":true})");
        ESP_LOGI(TAG, "Rebooting...");
        xTaskCreate([](void *ctx) {
            // 延迟500ms后重启
            vTaskDelay(pdMS_TO_TICKS(500));
            esp_restart();
        }, "reboot_task", 4096, nullptr, 5, NULL);
    });
    server_->on("/advanced/config", [this](AsyncWebServerRequest* req) {
        std::string json = R"({"ota_url":")" + ota_url_ + R"(",)";
        json += R"("max_tx_power":)" + std::to_string(max_tx_power_) + R"(,)";
        json += R"("remember_bssid":)" + std::to_string(remember_bssid_) + R"(,)";
        json += R"("sleep_mode":)" + std::to_string(sleep_mode_) + R"(})";
        req->send(200, "application/json", json);
    });
    server_->on("/advanced/submit", HTTP_POST, 
        [](AsyncWebServerRequest *req){},
        nullptr,
        [this](AsyncWebServerRequest *req, uint8_t *data, size_t len, size_t index, size_t total) {
            if (total > 1024) {
                req->send(400, "text/plain", "Payload too large");
            }

            // 针对小的数据块进行优化
            const char* json_ptr = nullptr;
            if (len == total) {
                json_ptr = (const char*)data;
            } else {
                if (index == 0) {
                    json_.clear();
                }
                json_.append((char*)data, len);
                if (index + len == total) {
                    json_ptr = json_.c_str();
                }
            }
            
            if (json_ptr) {
                auto* json = cJSON_Parse(json_ptr);
                if (!json) {
                    req->send(400, "Invalid JSON.");
                } 

                MyNVS nvs("wifi", NVS_READWRITE);
                
                auto *ota_url = cJSON_GetObjectItem(json, "ota_url");
                esp_err_t err = ESP_OK;
                if (cJSON_IsString(ota_url) && ota_url->valuestring) {
                    ota_url_ = ota_url->valuestring;
                    err = nvs.write("ota_url", ota_url_);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "Failed to save OTA URL: %d", err);
                    }
                }
                auto *max_tx_power = cJSON_GetObjectItem(json, "max_tx_power");
                if (cJSON_IsNumber(max_tx_power)) {
                    max_tx_power_ = max_tx_power->valueint;
                    err = esp_wifi_set_max_tx_power(max_tx_power_);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "Failed to set WiFi power: %d", err);
                        req->send(500, "text/plain", "Failed to set WiFi power");
                    }
                    err = nvs.write("max_tx_power", max_tx_power_);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "Failed to save WiFi power: %d", err);
                    }
                }
                // 保存BSSID记忆设置
                auto *remember_bssid = cJSON_GetObjectItem(json, "remember_bssid");
                if (cJSON_IsBool(remember_bssid)) {
                    remember_bssid_ = cJSON_IsTrue(remember_bssid);
                    err = nvs.write("remember_bssid", remember_bssid_);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "Failed to save remember_bssid: %d", err);
                    }
                }
                // 保存睡眠模式设置
                auto *sleep_mode = cJSON_GetObjectItem(json, "sleep_mode");
                if (cJSON_IsBool(sleep_mode)) {
                    sleep_mode_ = cJSON_IsTrue(sleep_mode);
                    err = nvs.write("sleep_mode", sleep_mode_);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "Failed to save sleep_mode: %d", err);
                    }
                }
                req->send(200, "application/json", R"({"success":true})");
                cJSON_Delete(json);
            }
        }
    );

    // 强制所有未注册的路由转至门户
    server_->onNotFound([](AsyncWebServerRequest* req){
        req->send(404, "text/plain", page404);
    });
    server_->begin();
}

/// @brief 设置AP SSID前缀
void MyWifi::SetApSsid(const std::string&& prefix)
{
    uint8_t mac[6];

    ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP));
    char ssid[32];
    snprintf(ssid, sizeof(ssid), "%s-%02X%02X", prefix.c_str(), mac[4], mac[5]);
    ap_ssid_ = ssid;
}

