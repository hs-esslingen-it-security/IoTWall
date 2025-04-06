#include "eval_api.hpp"

#include <esp_system.h>
#include <esp_log.h>
#include <esp_heap_caps.h>
#include <sdkconfig.h>

#include "perf_measurements.hpp"

char EvalApi::error_msg[100] = "";

constexpr httpd_uri_t EvalApi::uri_post_restart_device;
constexpr httpd_uri_t EvalApi::uri_get_uptime;
constexpr httpd_uri_t EvalApi::uri_get_memory_use;
#if PERFORMANCE_MEASUREMENTS_ENABLED
constexpr httpd_uri_t EvalApi::uri_post_firewall_performance_measurements_status;
constexpr httpd_uri_t EvalApi::uri_get_firewall_performance_measurements_results;
#endif

const char TAG[] = "eval_api";

EvalApi::EvalApi(const uint16_t port, const uint16_t ctrl_port)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = port;
    config.ctrl_port = ctrl_port;
    config.uri_match_fn = httpd_uri_match_wildcard;

    if (httpd_start(&server, &config) != ESP_OK)
    {
        ESP_LOGE(TAG, "Error starting Eval API");
        return;
    }

    httpd_register_uri_handler(server, &EvalApi::uri_post_restart_device);
    httpd_register_uri_handler(server, &EvalApi::uri_get_uptime);
    httpd_register_uri_handler(server, &EvalApi::uri_get_memory_use);
#if PERFORMANCE_MEASUREMENTS_ENABLED
    httpd_register_uri_handler(server, &EvalApi::uri_post_firewall_performance_measurements_status);
    httpd_register_uri_handler(server, &EvalApi::uri_get_firewall_performance_measurements_results);
#endif

    ESP_LOGI(TAG, "EvalApi started on port %u", port);
}

EvalApi::~EvalApi()
{
    httpd_stop(server);
    ESP_LOGI(TAG, "EvalApi stopped");
}

int EvalApi::parse_json(cJSON *&json_buf, char *buf)
{

    const char *parse_error_ptr;
    json_buf = cJSON_ParseWithOpts(buf, &parse_error_ptr, true);

    if (json_buf == NULL)
    {
        if (parse_error_ptr != NULL)
        {
            snprintf(error_msg, 100, "Error parsing JSON. Error before: %s", parse_error_ptr);
            ESP_LOGE(TAG, "%s", error_msg);

            return EVAL_API_ERR_INPUT;
        }
        else
        {
            strlcpy(error_msg, "Error parsing JSON. No error location available.", 49);
            ESP_LOGE(TAG, "%s", error_msg);

            return EVAL_API_ERR_INPUT;
        }
    }

    ESP_LOGD(TAG, "JSON parsed successfully");
    return EVAL_API_OK;
}

esp_err_t EvalApi::post_restart_device_handler(httpd_req_t *req)
{
    httpd_resp_send(req, "", HTTPD_RESP_USE_STRLEN);
    
    esp_restart();
}

esp_err_t EvalApi::get_uptime_handler(httpd_req_t *req)
{
    int64_t uptime = esp_timer_get_time();

    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "uptime", uptime);
    char json_str[55];
    cJSON_PrintPreallocated(json, json_str, 55, false);

    httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    cJSON_free(json);
    return ESP_OK;
}

esp_err_t EvalApi::get_memory_use_handler(httpd_req_t *req)
{
    // ESP_LOGI(TAG, "Main task handle: %p", main_task_handle);
    
    // char test_mem_str[11];
    // snprintf(test_mem_str, 11, "%u", main_task_min_free_stack);
    // ESP_LOGI(TAG, "Free stack main task (%p): %u", main_task_handle, main_task_min_free_stack);

    cJSON *json = cJSON_CreateObject();
    // cJSON *stackJson = cJSON_AddObjectToObject(json, "stack");
    cJSON *heapJson = cJSON_AddObjectToObject(json, "heap");

    // Stack (not needed, as the whole firewall is stored in heap)
    // // Minimum available free stack in words (1 word = 4 bytes)
    // UBaseType_t main_task_min_free_stack = uxTaskGetStackHighWaterMark(main_task_handle);
    // int main_task_stack_size = CONFIG_ESP_MAIN_TASK_STACK_SIZE;

    // // Total size of main task stack in bytes
    // cJSON_AddItemToObject(
    //     stackJson,
    //     "total_size",
    //     cJSON_CreateNumber(main_task_stack_size)
    // );

    // // Minimum amount of memory that was available in the stack since boot in bytes
    // cJSON_AddItemToObject(
    //     stackJson,
    //     "min_free",
    //     cJSON_CreateNumber(main_task_min_free_stack * 4)
    // );

    // Heap
    multi_heap_info_t heap_info;
    heap_caps_get_info(&heap_info, MALLOC_CAP_DEFAULT);
    // size_t total_heap = heap_info.total_free_bytes + heap_info.total_allocated_bytes;
    size_t total_heap = heap_caps_get_total_size(MALLOC_CAP_DEFAULT);
    // uint32_t min_free_heap = esp_get_minimum_free_heap_size();
    // ESP_LOGI(TAG, "min get_info: %u; min_free_heap_size(): %u", heap_info.minimum_free_bytes, min_free_heap);

    // Total heap size in bytes
    cJSON_AddItemReferenceToObject(
        heapJson,
        "total",
        cJSON_CreateNumber(total_heap)
    );

    // Minimum amount of memory that was available in the heap since boot in bytes
    cJSON_AddItemToObject(
        heapJson,
        "min_free",
        cJSON_CreateNumber(heap_info.minimum_free_bytes)
    );

    // Get task handle of the lwIP task
    TaskHandle_t lwip_task_handle = xTaskGetHandle("tiT");
    // ~0 = error
    UBaseType_t lwip_task_min_free_stack = ~0;

    if (lwip_task_handle == NULL)
    {
        ESP_LOGE(TAG, "Error getting lwIP task");
    }
    else
    {
        lwip_task_min_free_stack = uxTaskGetStackHighWaterMark(lwip_task_handle);
    }

    cJSON *lwip_stack_json = cJSON_AddObjectToObject(json, "lwip_stack");

    // Total size of main task stack in bytes
    cJSON_AddItemToObject(
        lwip_stack_json,
        "total",
        cJSON_CreateNumber(CONFIG_LWIP_TCPIP_TASK_STACK_SIZE)
    );

    // Minimum amount of memory that was available in the stack since boot in bytes
    cJSON_AddItemToObject(
        lwip_stack_json,
        "min_free",
        cJSON_CreateNumber(lwip_task_min_free_stack)
    );

    char *json_str = cJSON_Print(json);

    httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    cJSON_free(json);
    free(json_str);
    return ESP_OK;
}

#if PERFORMANCE_MEASUREMENTS_ENABLED
esp_err_t EvalApi::post_firewall_performance_measurements_status_handler(httpd_req_t *req)
{
    char *buf = nullptr;
    cJSON *json = nullptr;

    size_t buf_len = req->content_len;
    if (buf_len == 0)
    {
        // Request has no body
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Value expected in request body");
        return ESP_OK;
    }
    
    buf = new char[buf_len + 1];
    int ret = httpd_req_recv(req, buf, buf_len);

    if (ret <= 0)
    {
        // Error receiving body
        if (ret == HTTPD_SOCK_ERR_TIMEOUT)
        {
            httpd_resp_send_408(req);
        }

        delete buf;
        return ESP_FAIL;
    }

    // Request body is available
    // Add \0
    buf[buf_len] = '\0';

    int err = parse_json(json, buf);

    if (err != EVAL_API_OK)
    {
        if (err == EVAL_API_ERR_INPUT)
        {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, error_msg);
        }
        else
        {
            // FW_ERR
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Internal Server Error");
        }

        delete buf;
        cJSON_Delete(json);
        return ESP_OK;
    }

    if (!cJSON_IsObject(json))
    {
        const char msg[] = "Expected JSON object as JSON root";
        ESP_LOGE(TAG, "%s", msg);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, msg);

        delete buf;
        cJSON_Delete(json);
        return ESP_OK;
    }

    cJSON *json_enabled_key = cJSON_GetObjectItem(json, "enabled");

    if (json_enabled_key == NULL)
    {
        const char msg[] = "Missing \"enabled\" key";
        ESP_LOGE(TAG, "%s", msg);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, msg);

        delete buf;
        cJSON_Delete(json);
        return ESP_OK;
    }

    if (!cJSON_IsBool(json_enabled_key))
    {
        const char msg[] = "Expected \"enabled\" key to be boolean";
        ESP_LOGE(TAG, "%s", msg);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, msg);

        delete buf;
        cJSON_Delete(json);
        return ESP_OK;
    }

    bool enabled = cJSON_IsTrue(json_enabled_key);

    // httpd
    httpd_resp_send(req, "", HTTPD_RESP_USE_STRLEN);

    // Enabled/disable measurements after response was sent to prevent measuring API packets
    if (enabled)
        PerfMeasurements::enable_firewall_latency_measurement();
    else
        // Disable and discard the last three packets, as they were caused by this HTTP request
        // (possibly SYN, ACK, Data)
        PerfMeasurements::disable_firewall_latency_measurement(3);

    delete buf;
    cJSON_Delete(json);
    return ESP_OK;
}

esp_err_t EvalApi::get_firewall_performance_measurements_results_handler(httpd_req_t *req)
{
    int *measurements = PerfMeasurements::get_firewall_latency_measurements();
    int measurements_count = PerfMeasurements::get_firewall_latency_measurements_count();

    if (measurements_count == 0)
    {
        httpd_resp_send(req, "[]", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    ESP_LOGD(TAG, "measurement count: %i", measurements_count);

    // cJSON *json = cJSON_CreateIntArray(measurements, measurements_count);

    // buf_size consists of the following:
    // - 11 bytes for each number (int = max 10 chars + comma)
    // - 10 bytes for JSON formatting with square brackets + \0 + some additional space to be safe
    // This expects that the JSON is printed without whitespace or newlines
    const int buf_size = measurements_count * 11 + 10;
    ESP_LOGD(TAG, "buf_size: %i", buf_size);

    char *json_str = new char[buf_size];
    // This did not work with cJSON (doesn't get along with that amount of data for some reason)
    // int res = cJSON_PrintPreallocated(json, json_str, buf_size, false);

    char *buf_pos = json_str;
    int remaining_space;
    int written;
    // char fragment[12]; // number + comma + \0
    *buf_pos = '[';
    buf_pos++;
    // Note: this only works if measurement_count is > 0
    for (int i = 0; i < measurements_count - 1; i++)
    {
        remaining_space = buf_size - (buf_pos - json_str);
        written = snprintf(buf_pos, remaining_space , "%i,", measurements[i]);
        buf_pos += written;

        if (written < 0 || written >= remaining_space)
        {
            char msg[] = "Error printing JSON";
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, msg);
            ESP_LOGE(TAG, "%s", msg);
            delete json_str;
            return ESP_OK;
        }
    }

    remaining_space = buf_size - (buf_pos - json_str);
    written = snprintf(buf_pos, buf_size - (buf_pos - json_str) , "%i]", measurements[measurements_count - 1]);
    buf_pos += written + 1; // + 1 because of \0

    if (written < 0 || written >= remaining_space)
    {
        char msg[] = "Error printing JSON end";
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, msg);
        ESP_LOGE(TAG, "%s", msg);
        delete json_str;
        return ESP_OK;
    }

    // if (res == 0)
    // {
    //     char msg[] = "Error printing JSON";
    //     ESP_LOGE(TAG, "%s", msg);
    //     httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, msg);
    //     cJSON_Delete(json);
    //     delete json_str;
    //     return ESP_OK;
    // }

    ESP_LOGD(TAG, "Created JSON. Length: %i", strlen(json_str));

    // Stream response because if the response is too large, it does not fit into TCP_SND_BUF (default 5744 bytes)
    for (int i = 0; i < strlen(json_str); i+=1000)
    {
        int len = strlen(json_str + i) < 1000 ? strlen(json_str + i) : 1000;
        httpd_resp_send_chunk(req, json_str + i, len);
    }

    httpd_resp_send_chunk(req, "", 0);

    // cJSON_Delete(json);
    delete json_str;
    return ESP_OK;
}
#endif
