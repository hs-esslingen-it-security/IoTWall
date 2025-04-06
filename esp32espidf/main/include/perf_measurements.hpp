#include "config.h"
#if PERFORMANCE_MEASUREMENTS_ENABLED == 1
#ifndef __PERF_MEASUREMENTS_H__
#define __PERF_MEASUREMENTS_H__

#include <stdint.h>

/**
 * Class for firewall performance measurements (for evaluation purposes only, not for production use)
 */
class PerfMeasurements {
    public:
        /** Buffer size for firewall latency measurements
         * (i.e., max number of measurements that can be stored at the same time)
         */
        static const int FIREWALL_LATENCY_MEASUREMENTS_BUF = 10000;

        static void enable_firewall_latency_measurement();
        /**
         * Disables latency measurement (no more measurements can be added to the array)
         * 
         * @param discard_count Removes the given number of measurements (starting from the end).
         * This allows to remove measurements that, e.g, were added by packets from the REST API call
         * that arrived to disable the measurement.
         */
        static void disable_firewall_latency_measurement(int discard_count);
        /** Returns true if measurement is enabled, otherwise false */
        static bool get_firewall_latency_measurement_status();

        static void start_firewall_latency_measurement();
        /**
         * Stops a measurement, calculates the latency, and saves the result
         */
        static void stop_firewall_latency_measurement();

        static int *get_firewall_latency_measurements();
        /**
         * Number of measurements stored in the buffer (maximum is FIREWALL_LATENCY_MEASUREMENTS_BUF)
         */
        static int get_firewall_latency_measurements_count();

    private:
        static bool firewall_latency_measurement_enabled;
        /** Start time of the latest measurement */
        static int64_t firewall_latency_measurement_start;

        static void append_firewall_latency_measurements(int value);

        static int firewall_latency_measurements[FIREWALL_LATENCY_MEASUREMENTS_BUF];
        static int firewall_latency_measurements_head;
        static int firewall_latency_measurements_tail;
        static bool firewall_latency_measurements_is_full;
};

#endif
#endif
