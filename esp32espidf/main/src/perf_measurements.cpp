#include "perf_measurements.hpp"

#if PERFORMANCE_MEASUREMENTS_ENABLED == 1

#include <esp_timer.h>

bool PerfMeasurements::firewall_latency_measurement_enabled = false;
int64_t PerfMeasurements::firewall_latency_measurement_start = 0;
int PerfMeasurements::firewall_latency_measurements[PerfMeasurements::FIREWALL_LATENCY_MEASUREMENTS_BUF] = {};
int PerfMeasurements::firewall_latency_measurements_head = 0;
int PerfMeasurements::firewall_latency_measurements_tail = 0;
bool PerfMeasurements::firewall_latency_measurements_is_full = false;
// int PerfMeasurements::firewall_latency_measurements_index = 0;

void PerfMeasurements::enable_firewall_latency_measurement()
{
    // Reset previous measurements
    // firewall_latency_measurements_index = 0;
    firewall_latency_measurements_head = 0;
    firewall_latency_measurements_tail = 0;
    firewall_latency_measurements_is_full = false;
    firewall_latency_measurement_start = 0;

    firewall_latency_measurement_enabled = true;
}

void PerfMeasurements::disable_firewall_latency_measurement(int discard_count)
{
    firewall_latency_measurement_enabled = false;

    // if (discard_count > firewall_latency_measurements_index)
    //     firewall_latency_measurements_index = 0;
    // else
    //     firewall_latency_measurements_index -= discard_count;

    if (discard_count >= get_firewall_latency_measurements_count())
    {
        firewall_latency_measurements_head = 0;
        firewall_latency_measurements_tail = 0;
        firewall_latency_measurements_is_full = false;
    }
    else
    {
        firewall_latency_measurements_head = (firewall_latency_measurements_head - discard_count) % FIREWALL_LATENCY_MEASUREMENTS_BUF;
        if (firewall_latency_measurements_head < 0)
            firewall_latency_measurements_head = FIREWALL_LATENCY_MEASUREMENTS_BUF - firewall_latency_measurements_head;
        firewall_latency_measurements_is_full = false;
    }
}

bool PerfMeasurements::get_firewall_latency_measurement_status()
{
    return firewall_latency_measurement_enabled;
}

void PerfMeasurements::start_firewall_latency_measurement()
{
    if (!firewall_latency_measurement_enabled)
        return;

    firewall_latency_measurement_start = esp_timer_get_time();
}

void PerfMeasurements::stop_firewall_latency_measurement()
{
    if (!firewall_latency_measurement_enabled)
        return;

    int64_t end = esp_timer_get_time();
    // Conversion to int should be no problem because we don't measure durations in the range of seconds or more
    int latency = (int)(end - firewall_latency_measurement_start);
    append_firewall_latency_measurements(latency);
    
    

    // firewall_latency_measurements[firewall_latency_measurements_index] = latency;
    // firewall_latency_measurements_index++;

    // if (firewall_latency_measurements_index >= PerfMeasurements::FIREWALL_LATENCY_MEASUREMENTS_BUF)
    // {
    //     // Start from beginning
    //     firewall_latency_measurements_index = 0;
    // }
}

int *PerfMeasurements::get_firewall_latency_measurements()
{
    return firewall_latency_measurements;
}

int PerfMeasurements::get_firewall_latency_measurements_count()
{
    if (firewall_latency_measurements_is_full)
        return FIREWALL_LATENCY_MEASUREMENTS_BUF;
    else if (firewall_latency_measurements_tail == firewall_latency_measurements_head)
        return 0;
    else if (firewall_latency_measurements_tail > 0)
        // return firewall_latency_measurements_head + (FIREWALL_LATENCY_MEASUREMENTS_BUF - firewall_latency_measurements_tail);
        return FIREWALL_LATENCY_MEASUREMENTS_BUF - (firewall_latency_measurements_tail - firewall_latency_measurements_head);
    else
        return firewall_latency_measurements_head;
    // return firewall_latency_measurements_index;
}

void PerfMeasurements::append_firewall_latency_measurements(int value)
{
    firewall_latency_measurements[firewall_latency_measurements_head] = value;
    firewall_latency_measurements_head =
            (firewall_latency_measurements_head + 1) % FIREWALL_LATENCY_MEASUREMENTS_BUF;

    if (firewall_latency_measurements_head == firewall_latency_measurements_tail)
    {
        firewall_latency_measurements_is_full = true;
    }
    
    if (
        firewall_latency_measurements_is_full
        && firewall_latency_measurements_tail != firewall_latency_measurements_head
    ) {
        firewall_latency_measurements_tail =
            (firewall_latency_measurements_tail + 1) % FIREWALL_LATENCY_MEASUREMENTS_BUF;
    }
}
#endif
