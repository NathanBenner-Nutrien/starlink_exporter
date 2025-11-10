// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/alecthomas/kingpin.v2"
)

const namespace = "starlink" // For Prometheus metrics.

type metricInfo struct {
	Desc *prometheus.Desc
	Type prometheus.ValueType
}

type metricTypes map[string]metricInfo

func newMetric(metricName string, docString string, t prometheus.ValueType, variableLabels []string, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", metricName),
			docString,
			variableLabels,
			constLabels,
		),
		Type: t,
	}
}

// Define metrics here
var (
	metrics = metricTypes{
		"count": newMetric(
			"count",
			"Total count of user terminal, router or ip allocation.",
			prometheus.GaugeValue,
			[]string{"type", "account_number"}, nil),

		// User Terminal Metrics

		"downlink_throughput": newMetric(
			"downlink_throughput",
			"Downlink throughput in Mbps.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"uplink_throughput": newMetric(
			"uplink_throughput",
			"Uplink throughput in Mbps.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"ping_drop_rate": newMetric(
			"ping_drop_rate",
			"Average ping drop rate.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"ping_latency": newMetric(
			"ping_latency",
			"Average ping latency in milliseconds.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"obstruction_percent_time": newMetric(
			"obstruction_percent_time",
			"Obstruction percentage time.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"signal_quality": newMetric(
			"signal_quality",
			"Signal quality.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		// Router metrics

		"wifi_uptime": newMetric(
			"wifi_uptime",
			"Wifi uptime in seconds.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"wifi_clients_total": newMetric(
			"wifi_clients_total",
			"Total number of WiFi clients.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "connection"}, nil),

		"wifi_is_repeater": newMetric(
			"wifi_is_repeater",
			"Router is in repeater mode.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"wifi_hops_from_controller": newMetric(
			"wifi_hops_from_controller",
			"Router mesh hops from controller. 0 means router is directly connected to Starlink user terminal. -1 means invalid.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"wifi_is_bypassed": newMetric(
			"wifi_is_bypassed",
			"Router wifi is bypassed.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"internet_ping_drop_rate": newMetric(
			"internet_ping_drop_rate",
			"Approximate packet loss. Pings are lower priority than other traffic so this may overestimate packet loss if the network is congested.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"internet_ping_latency": newMetric(
			"internet_ping_latency",
			"Average latency from the Starlink router to the internet.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"wifi_pop_ping_drop_rate": newMetric(
			"wifi_pop_ping_drop_rate",
			"Approximate packet loss to the Starlink point of presence.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"wifi_pop_ping_latency": newMetric(
			"wifi_pop_ping_latency",
			"Approximate latency from the Starlink router to the Starlink point of presence.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"dish_ping_drop_rate": newMetric(
			"dish_ping_drop_rate",
			"Approximate packet loss to Starlink user terminal.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"dish_ping_latency": newMetric(
			"dish_ping_latency",
			"Approximate latency from the Starlink router to the Starlink user terminal.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"wan_rx": newMetric(
			"wan_rx",
			"Downlink usage in bytes.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"wan_tx": newMetric(
			"wan_tx",
			"Uplink usage in bytes.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"wifi_clients_rx_rate_min": newMetric(
			"wifi_clients_rx_rate_min",
			"Minimum receive rate of clients.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "signal_band"}, nil),

		"wifi_clients_tx_rate_min": newMetric(
			"wifi_clients_tx_rate_min",
			"Minimum transfer rate of clients.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "signal_band"}, nil),

		"wifi_clients_rx_rate_max": newMetric(
			"wifi_clients_rx_rate_max",
			"Maximum receive rate of clients.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "signal_band"}, nil),

		"wifi_clients_tx_rate_max": newMetric(
			"wifi_clients_tx_rate_max",
			"Maximum transfer rate of clients.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "signal_band"}, nil),

		"wifi_clients_rx_rate_avg": newMetric(
			"wifi_clients_rx_rate_avg",
			"Average receive rate of clients.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "signal_band"}, nil),

		"wifi_clients_tx_rate_avg": newMetric(
			"wifi_clients_tx_rate_avg",
			"Average transfer rate of clients.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "signal_band"}, nil),

		"wifi_clients_signal_strength_min": newMetric(
			"wifi_clients_signal_strength_min",
			"Minimum signal strength of clients.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "signal_band"}, nil),

		"wifi_clients_signal_strength_max": newMetric(
			"wifi_clients_signal_strength_max",
			"Maximum signal strength of clients.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "signal_band"}, nil),

		"wifi_clients_signal_strength_avg": newMetric(
			"wifi_clients_signal_strength_avg",
			"Average signal strength of clients.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "signal_band"}, nil),

		// IP allocation metrics

		"ip_allocation": newMetric(
			"ip_allocation",
			"IP allocation information.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "ipv4", "ipv6Ue", "ipv6Cpe"}, nil),

		// Metrics common to user terminals and routers

		"uptime": newMetric(
			"uptime",
			"Device uptime in seconds.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"active_alert_count": newMetric(
			"active_alert_count",
			"Number of active alerts.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name"}, nil),

		"alert": newMetric(
			"alert",
			"Starlink alert.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "account_number", "site_name", "alert_type"}, nil),
	}

	starlinkUp = prometheus.NewDesc(prometheus.BuildFQName("starlink", "", "up"), "Was the last scrape of starlink successful.", nil, nil)
)

// Exporter collects stats from the given URI and exports them using
// the prometheus metrics package.
type Exporter struct {
	URI            string
	authUri        string
	id             string
	secret         string
	accountNumbers []string
	sslVerify      bool
	proxyFromEnv   bool
	timeout        time.Duration
	mutex          sync.RWMutex
	up             prometheus.Gauge
	totalScrapes   prometheus.Counter
	metrics        metricTypes
	logger         log.Logger
}

// NewExporter returns an initialized Exporter.
func NewExporter(uri string, authUri string, id string, secret string, accountNumbers string, sslVerify bool, proxyFromEnv bool, timeout time.Duration, logger log.Logger) (*Exporter, error) {
	return &Exporter{
		URI:            uri,
		authUri:        authUri,
		id:             id,
		secret:         secret,
		accountNumbers: strings.Split(accountNumbers, ","),
		sslVerify:      sslVerify,
		proxyFromEnv:   proxyFromEnv,
		timeout:        timeout,
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "starlink",
			Name:      "up",
			Help:      "Was the last scrape of starlink successful.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "starlink",
			Name:      "exporter_scrapes_total",
			Help:      "Current total scrapes.",
		}),
		metrics: metrics,
		logger:  logger,
	}, nil
}

// Describe describes all the metrics ever exported by the starlink exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range metrics {
		ch <- m.Desc
	}
}

// Collect fetches the stats from starlink and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock() // To protect metrics from concurrent collects.
	defer e.mutex.Unlock()

	up := e.scrape(ch)

	ch <- prometheus.MustNewConstMetric(starlinkUp, prometheus.GaugeValue, up)
	ch <- e.totalScrapes
}

// Define data structures for Starlink API
type TokenResponse struct {
	Token     string `json:"access_token"`
	Expiry    int    `json:"expires_in"`
	TokenType string `json:"token_type"`
	Scope     string `json:"scope"`
}

type TelemetryRequestBody struct {
	AccountNumber string `json:"accountNumber"`
	BatchSize     int    `json:"batchSize"`
	MaxLingerMs   int    `json:"maxLingerMs"`
}

type TelemetryResponse struct {
	Data     TelemetryData     `json:"data"`
	MetaData TelemetryMetadata `json:"metadata"`
}

type TelemetryData struct {
	Values  [][]any             `json:"values"`
	Columns map[string][]string `json:"columnNamesByDeviceType"`
}

type TelemetryMetadata struct {
	Enumerators TelemetryEnumerators `json:"enums"`
}

type TelemetryEnumerators struct {
	DeviceType       map[string]string            `json:"DeviceType"`
	AlertEnumerators map[string]map[string]string `json:"AlertsByDeviceType"`
}

type ServiceLineResponse struct {
	Content ServiceLineResponseContent `json:"content"`
}

type ServiceLineResponseContent struct {
	TotalCount int           `json:"totalCount"`
	PageIndex  int           `json:"pageIndex"`
	Limit      int           `json:"limit"`
	IsLastPage bool          `json:"isLastPage"`
	Results    []ServiceLine `json:"results"`
}

type ServiceLine struct {
	AddressReferenceID string `json:"addressReferenceId"`
	ServiceLineNumber  string `json:"serviceLineNumber"`
	Nickname           string `json:"nickname"`
	Active             bool   `json:"active"`
}

type UserTerminalResponse struct {
	Content UserTerminalResponseContent `json:"content"`
}

type UserTerminalResponseContent struct {
	TotalCount int            `json:"totalCount"`
	PageIndex  int            `json:"pageIndex"`
	Limit      int            `json:"limit"`
	IsLastPage bool           `json:"isLastPage"`
	Results    []UserTerminal `json:"results"`
}

type UserTerminal struct {
	UserTerminalID    string `json:"userTerminalId"`
	ServiceLineNumber string `json:"serviceLineNumber"`
	Active            bool   `json:"active"`
}

func (e *Exporter) fetchToken() (string, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !e.sslVerify}}
	if e.proxyFromEnv {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := http.Client{
		Timeout:   e.timeout,
		Transport: tr,
	}

	requestBody := url.Values{
		"client_id":     {e.id},
		"client_secret": {e.secret},
		"grant_type":    {"client_credentials"},
	}

	req, err := http.NewRequest("POST", e.authUri, strings.NewReader(requestBody.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response, err := client.Do(req)

	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if !(response.StatusCode >= 200 && response.StatusCode < 300) {
		return "", fmt.Errorf("HTTP status %d", response.StatusCode)
	}

	var data TokenResponse
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %s", err)
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("error parsing response: %s", err)
	}

	return data.Token, nil
}

func (e *Exporter) fetchTelemetry(token string, accountNumber string) (TelemetryResponse, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !e.sslVerify}}
	if e.proxyFromEnv {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := http.Client{
		Timeout:   e.timeout,
		Transport: tr,
	}

	// level.Info(e.logger).Log("msg", "Fetching telemetry", "uri", e.URI+"/telemetry/stream/v1/telemetry", "account number", accountNumber)

	requestBody := TelemetryRequestBody{AccountNumber: accountNumber, BatchSize: 2000, MaxLingerMs: 5000}
	jsonRequestBody, err := json.Marshal(requestBody)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error marshalling JSON %v", err)
		return TelemetryResponse{}, errors.New("error fetching telemetry")
	}

	req, err := http.NewRequest("POST", e.URI+"/telemetry/stream/v1/telemetry", bytes.NewBuffer(jsonRequestBody))
	if err != nil {
		level.Error(e.logger).Log("msg", "Error creating request", "err", err)
		return TelemetryResponse{}, errors.New("error fetching telemetry")
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	response, err := client.Do(req)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error fetching telemetry", "err", err)
		return TelemetryResponse{}, errors.New("error fetching telemetry")
	}
	defer response.Body.Close()

	if !(response.StatusCode >= 200 && response.StatusCode < 300) {
		level.Error(e.logger).Log("msg", "Error fetching telemetry", "status", response.StatusCode)
		return TelemetryResponse{}, errors.New("error fetching telemetry")
	}

	var telemetryResponse TelemetryResponse
	body, err := io.ReadAll(response.Body)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error reading response body", "err", err)
		return TelemetryResponse{}, errors.New("error fetching telemetry")
	}
	if err := json.Unmarshal(body, &telemetryResponse); err != nil {
		level.Error(e.logger).Log("msg", "Error unmarshaling response body", "err", err)
		return TelemetryResponse{}, errors.New("error fetching telemetry")
	}

	return telemetryResponse, nil
}

func (e *Exporter) fetchServiceLines(token string, accountNumber string, page int) (ServiceLineResponse, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !e.sslVerify}}
	if e.proxyFromEnv {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := http.Client{
		Timeout:   e.timeout,
		Transport: tr,
	}

	// level.Info(e.logger).Log("msg", "Fetching service lines", "uri", e.URI+"/enterprise/v1/account/"+accountNumber+"/service-lines?page="+strconv.Itoa(page))

	req, err := http.NewRequest("GET", e.URI+"/enterprise/v1/account/"+accountNumber+"/service-lines?page="+strconv.Itoa(page), nil)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error creating request", "err", err)
		return ServiceLineResponse{}, errors.New("error fetching service lines")
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Accept", "application/json")

	response, err := client.Do(req)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error fetching service lines", "err", err)
		return ServiceLineResponse{}, errors.New("error fetching service lines")
	}
	defer response.Body.Close()

	if !(response.StatusCode >= 200 && response.StatusCode < 300) {
		level.Error(e.logger).Log("msg", "Error fetching service lines", "status", response.StatusCode)
		return ServiceLineResponse{}, errors.New("error fetching service lines")
	}

	var serviceLinesResponse ServiceLineResponse
	body, err := io.ReadAll(response.Body)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error reading response body", "err", err)
		return ServiceLineResponse{}, errors.New("error fetching service lines")
	}

	if err := json.Unmarshal(body, &serviceLinesResponse); err != nil {
		level.Error(e.logger).Log("msg", "Error unmarshaling response body", "err", err)
		return ServiceLineResponse{}, errors.New("error fetching service lines")
	}

	return serviceLinesResponse, nil
}

func (e *Exporter) fetchUserTerminals(token string, accountNumber string, page int) (UserTerminalResponse, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !e.sslVerify}}
	if e.proxyFromEnv {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := http.Client{
		Timeout:   e.timeout,
		Transport: tr,
	}

	// level.Info(e.logger).Log("msg", "Fetching user terminals", "uri", e.URI+"/enterprise/v1/account/"+accountNumber+"/user-terminals?page="+strconv.Itoa(page))

	req, err := http.NewRequest("GET", e.URI+"/enterprise/v1/account/"+accountNumber+"/user-terminals?page="+strconv.Itoa(page), nil)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error creating request", "err", err)
		return UserTerminalResponse{}, errors.New("error fetching user terminals")
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Accept", "application/json")

	response, err := client.Do(req)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error fetching user terminals", "err", err)
		return UserTerminalResponse{}, errors.New("error fetching user terminals")
	}
	defer response.Body.Close()

	if !(response.StatusCode >= 200 && response.StatusCode < 300) {
		level.Error(e.logger).Log("msg", "Error fetching user terminals", "status", response.StatusCode)
		return UserTerminalResponse{}, errors.New("error fetching user terminals")
	}

	var userTerminalResponse UserTerminalResponse
	body, err := io.ReadAll(response.Body)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error reading response body", "err", err)
		return UserTerminalResponse{}, errors.New("error fetching user terminals")
	}
	if err := json.Unmarshal(body, &userTerminalResponse); err != nil {
		level.Error(e.logger).Log("msg", "Error unmarshaling response body", "err", err)
		return UserTerminalResponse{}, errors.New("error fetching user terminals")
	}

	return userTerminalResponse, nil
}

func (e *Exporter) gatherMetrics(ch chan<- prometheus.Metric, token string, accountNumber string) (map[string]int, error) {

	defer func() {
		if r := recover(); r != nil {
			level.Error(e.logger).Log("msg", "Recovered from panic:", r)
		}
	}()

	totalObjects := map[string]int{
		"service_line":  0,
		"user_terminal": 0,
		"router":        0,
		"ip_allocation": 0,
	}

	// Collect service lines from management API
	serviceLines := make([]ServiceLine, 0)
	for i := range 10 {
		serviceLineResponse, err := e.fetchServiceLines(token, accountNumber, i)
		if err != nil {
			level.Error(e.logger).Log("msg", "Error fetching service lines", "error", err)
			return totalObjects, errors.New("error fetching service lines")
		}
		serviceLines = append(serviceLines, serviceLineResponse.Content.Results...)
		if len(serviceLines) >= serviceLineResponse.Content.TotalCount {
			totalObjects["service_line"] = serviceLineResponse.Content.TotalCount
			break
		}
	}

	// Count active service lines
	for _, sl := range serviceLines {
		if sl.Active {
			totalObjects["service_line"]++
		}
	}

	// Collect user terminals from management API
	userTerminals := make([]UserTerminal, 0)
	for i := range 10 {
		userTerminalResponse, err := e.fetchUserTerminals(token, accountNumber, i)
		if err != nil {
			level.Error(e.logger).Log("msg", "Error fetching user terminals", "error", err)
			return totalObjects, errors.New("error fetching user terminals")
		}
		userTerminals = append(userTerminals, userTerminalResponse.Content.Results...)
		if len(userTerminals) >= userTerminalResponse.Content.TotalCount {
			break
		}
	}

	// Count active user terminals
	for _, ut := range userTerminals {
		if ut.Active {
			totalObjects["user_terminal"]++
		}
	}

	// Create a map of user terminals to service lines for associating site names
	// Site names are configured with the nickname field on service lines
	userTerminalNameMap := mapUserTerminalNames(serviceLines, userTerminals)

	// Retry fetching telemetry until valid data is returned
	var telemetryResponse TelemetryResponse
	for range 5 {
		var err error
		telemetryResponse, err = e.fetchTelemetry(token, accountNumber)
		if err != nil {
			level.Error(e.logger).Log("msg", "Error fetching telemetry")
			return totalObjects, errors.New("error fetching telemetry")
		}
		if len(telemetryResponse.Data.Values) >= len(userTerminalNameMap) {
			break
		}
		level.Info(e.logger).Log("msg", "Telemetry did not return values", "num values", len(telemetryResponse.Data.Values))
		time.Sleep(1 * time.Second)
	}

	processedDevices := make(map[string]bool)

	for _, values := range telemetryResponse.Data.Values {
		if len(values) == 0 {
			continue
		}

		deviceType := values[0].(string)
		metrics := mapMetrics(values, telemetryResponse.Data.Columns[deviceType])

		switch deviceType {
		case "u":
			deviceType := "user_terminal"
			deviceID := metrics["DeviceId"].(string)
			siteName := userTerminalNameMap[deviceID]

			// Handle duplicate device IDs
			_, keyExists := processedDevices[deviceID]
			if keyExists {
				// level.Info(e.logger).Log("msg", "Duplicate device ID discovered", "device_id", deviceID)
				continue
			} else {
				processedDevices[deviceID] = true
			}

			ch <- prometheus.MustNewConstMetric(
				e.metrics["downlink_throughput"].Desc,
				e.metrics["downlink_throughput"].Type,
				metrics["DownlinkThroughput"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["uplink_throughput"].Desc,
				e.metrics["uplink_throughput"].Type,
				metrics["UplinkThroughput"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["ping_drop_rate"].Desc,
				e.metrics["ping_drop_rate"].Type,
				metrics["PingDropRateAvg"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["ping_latency"].Desc,
				e.metrics["ping_latency"].Type,
				metrics["PingLatencyMsAvg"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["obstruction_percent_time"].Desc,
				e.metrics["obstruction_percent_time"].Type,
				metrics["ObstructionPercentTime"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["uptime"].Desc,
				e.metrics["uptime"].Type,
				metrics["Uptime"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["signal_quality"].Desc,
				e.metrics["signal_quality"].Type,
				metrics["SignalQuality"].(float64), deviceID, deviceType, accountNumber, siteName)

			alerts := alertsToStrings(metrics["ActiveAlerts"].([]any))

			for alertID, alertType := range telemetryResponse.MetaData.Enumerators.AlertEnumerators["u"] {
				var metric float64
				if slices.Contains(alerts, alertID) {
					metric = 1.0
				} else {
					metric = 0.0
				}
				ch <- prometheus.MustNewConstMetric(
					e.metrics["alert"].Desc,
					e.metrics["alert"].Type,
					metric, deviceID, deviceType, accountNumber, siteName, alertType)
			}

			ch <- prometheus.MustNewConstMetric(
				e.metrics["active_alert_count"].Desc,
				e.metrics["active_alert_count"].Type,
				float64(len(alerts)), deviceID, deviceType, accountNumber, siteName)

		case "r":
			deviceType := "router"
			deviceID := metrics["DeviceId"].(string)
			userTerminal := metrics["DishId"].(string)
			siteName := userTerminalNameMap[userTerminal]

			// Handle duplicate device IDs
			_, keyExists := processedDevices[deviceID]
			if keyExists {
				continue
			} else {
				processedDevices[deviceID] = true
			}

			// totalObjects["router"]++

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wifi_uptime"].Desc,
				e.metrics["wifi_uptime"].Type,
				metrics["WifiUptimeS"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wifi_clients_total"].Desc,
				e.metrics["wifi_clients_total"].Type,
				metrics["Clients"].(float64), deviceID, deviceType, accountNumber, siteName, "all")

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wifi_clients_total"].Desc,
				e.metrics["wifi_clients_total"].Type,
				metrics["Clients2Ghz"].(float64), deviceID, deviceType, accountNumber, siteName, "2GHz")

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wifi_clients_total"].Desc,
				e.metrics["wifi_clients_total"].Type,
				metrics["Clients5Ghz"].(float64), deviceID, deviceType, accountNumber, siteName, "5GHz")

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wifi_clients_total"].Desc,
				e.metrics["wifi_clients_total"].Type,
				metrics["ClientsEth"].(float64), deviceID, deviceType, accountNumber, siteName, "eth")

			isRepeater := 0
			if metrics["WifiIsRepeater"].(bool) {
				isRepeater = 1
			}

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wifi_is_repeater"].Desc,
				e.metrics["wifi_is_repeater"].Type,
				float64(isRepeater), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wifi_hops_from_controller"].Desc,
				e.metrics["wifi_hops_from_controller"].Type,
				metrics["WifiHopsFromController"].(float64), deviceID, deviceType, accountNumber, siteName)

			isBypassed := 0
			if metrics["WifiIsBypassed"].(bool) {
				isBypassed = 1
			}

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wifi_is_bypassed"].Desc,
				e.metrics["wifi_is_bypassed"].Type,
				float64(isBypassed), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["internet_ping_drop_rate"].Desc,
				e.metrics["internet_ping_drop_rate"].Type,
				metrics["InternetPingDropRate"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["internet_ping_latency"].Desc,
				e.metrics["internet_ping_latency"].Type,
				metrics["InternetPingLatencyMs"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wifi_pop_ping_drop_rate"].Desc,
				e.metrics["wifi_pop_ping_drop_rate"].Type,
				metrics["WifiPopPingDropRate"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wifi_pop_ping_latency"].Desc,
				e.metrics["wifi_pop_ping_latency"].Type,
				metrics["WifiPopPingLatencyMs"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["dish_ping_drop_rate"].Desc,
				e.metrics["dish_ping_drop_rate"].Type,
				metrics["DishPingDropRate"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["dish_ping_latency"].Desc,
				e.metrics["dish_ping_latency"].Type,
				metrics["DishPingLatencyMs"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wan_rx"].Desc,
				e.metrics["wan_rx"].Type,
				metrics["WanRxBytes"].(float64), deviceID, deviceType, accountNumber, siteName)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wan_tx"].Desc,
				e.metrics["wan_tx"].Type,
				metrics["WanTxBytes"].(float64), deviceID, deviceType, accountNumber, siteName)

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_rx_rate_min"].Desc,
			// 	e.metrics["wifi_clients_rx_rate_min"].Type,
			// 	metrics["Clients2GhzRxRateMbpsMin"].(float64), deviceID, deviceType, accountNumber, siteName, "2GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_rx_rate_min"].Desc,
			// 	e.metrics["wifi_clients_rx_rate_min"].Type,
			// 	metrics["Clients5GhzRxRateMbpsMin"].(float64), deviceID, deviceType, accountNumber, siteName, "5GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_tx_rate_min"].Desc,
			// 	e.metrics["wifi_clients_tx_rate_min"].Type,
			// 	metrics["Clients2GhzTxRateMbpsMin"].(float64), deviceID, deviceType, accountNumber, siteName, "2GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_tx_rate_min"].Desc,
			// 	e.metrics["wifi_clients_tx_rate_min"].Type,
			// 	metrics["Clients5GhzTxRateMbpsMin"].(float64), deviceID, deviceType, accountNumber, siteName, "5GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_rx_rate_max"].Desc,
			// 	e.metrics["wifi_clients_rx_rate_max"].Type,
			// 	metrics["Clients2GhzRxRateMbpsMax"].(float64), deviceID, deviceType, accountNumber, siteName, "2GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_rx_rate_max"].Desc,
			// 	e.metrics["wifi_clients_rx_rate_max"].Type,
			// 	metrics["Clients5GhzRxRateMbpsMax"].(float64), deviceID, deviceType, accountNumber, siteName, "5GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_tx_rate_max"].Desc,
			// 	e.metrics["wifi_clients_tx_rate_max"].Type,
			// 	metrics["Clients2GhzTxRateMbpsMax"].(float64), deviceID, deviceType, accountNumber, siteName, "2GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_tx_rate_max"].Desc,
			// 	e.metrics["wifi_clients_tx_rate_max"].Type,
			// 	metrics["Clients5GhzTxRateMbpsMax"].(float64), deviceID, deviceType, accountNumber, siteName, "5GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_rx_rate_avg"].Desc,
			// 	e.metrics["wifi_clients_rx_rate_avg"].Type,
			// 	metrics["Clients2GhzRxRateMbpsAvg"].(float64), deviceID, deviceType, accountNumber, siteName, "2GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_rx_rate_avg"].Desc,
			// 	e.metrics["wifi_clients_rx_rate_avg"].Type,
			// 	metrics["Clients5GhzRxRateMbpsAvg"].(float64), deviceID, deviceType, accountNumber, siteName, "5GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_tx_rate_avg"].Desc,
			// 	e.metrics["wifi_clients_tx_rate_avg"].Type,
			// 	metrics["Clients2GhzTxRateMbpsAvg"].(float64), deviceID, deviceType, accountNumber, siteName, "2GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_tx_rate_avg"].Desc,
			// 	e.metrics["wifi_clients_tx_rate_avg"].Type,
			// 	metrics["Clients5GhzTxRateMbpsAvg"].(float64), deviceID, deviceType, accountNumber, siteName, "5GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_signal_strength_min"].Desc,
			// 	e.metrics["wifi_clients_signal_strength_min"].Type,
			// 	metrics["Clients2GhzSignalStrengthMin"].(float64), deviceID, deviceType, accountNumber, siteName, "2GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_signal_strength_min"].Desc,
			// 	e.metrics["wifi_clients_signal_strength_min"].Type,
			// 	metrics["Clients5GhzSignalStrengthMin"].(float64), deviceID, deviceType, accountNumber, siteName, "5GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_signal_strength_max"].Desc,
			// 	e.metrics["wifi_clients_signal_strength_max"].Type,
			// 	metrics["Clients2GhzSignalStrengthMax"].(float64), deviceID, deviceType, accountNumber, siteName, "2GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_signal_strength_max"].Desc,
			// 	e.metrics["wifi_clients_signal_strength_max"].Type,
			// 	metrics["Clients5GhzSignalStrengthMax"].(float64), deviceID, deviceType, accountNumber, siteName, "5GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_signal_strength_avg"].Desc,
			// 	e.metrics["wifi_clients_signal_strength_avg"].Type,
			// 	metrics["Clients2GhzSignalStrengthAvg"].(float64), deviceID, deviceType, accountNumber, siteName, "2GHz")

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["wifi_clients_signal_strength_avg"].Desc,
			// 	e.metrics["wifi_clients_signal_strength_avg"].Type,
			// 	metrics["Clients5GhzSignalStrengthAvg"].(float64), deviceID, deviceType, accountNumber, siteName, "5GHz")

			alerts := alertsToStrings(metrics["ActiveAlerts"].([]any))
			for alertID, alertType := range telemetryResponse.MetaData.Enumerators.AlertEnumerators["r"] {
				var metric float64
				if slices.Contains(alerts, alertID) {
					metric = 1.0
				} else {
					metric = 0.0
				}
				ch <- prometheus.MustNewConstMetric(
					e.metrics["alert"].Desc,
					e.metrics["alert"].Type,
					metric, deviceID, deviceType, accountNumber, siteName, alertType)
			}

			ch <- prometheus.MustNewConstMetric(
				e.metrics["active_alert_count"].Desc,
				e.metrics["active_alert_count"].Type,
				float64(len(alerts)), deviceID, deviceType, accountNumber, siteName)

		case "i":
			deviceType := "ip_allocation"
			deviceID := metrics["DeviceId"].(string)
			userTerminal := strings.TrimPrefix(deviceID, "ip-")
			siteName := userTerminalNameMap[userTerminal]

			// Handle duplicate device IDs
			_, keyExists := processedDevices[deviceID]
			if keyExists {
				continue
			} else {
				processedDevices[deviceID] = true
			}

			totalObjects["ip_allocation"]++

			ipv4 := metrics["Ipv4"].([]any)

			ipv4_addr := ""
			if len(ipv4) > 0 {
				ipv4_addr = ipv4[0].(string)
			}

			ipv6Ue := metrics["Ipv6Ue"].([]any)
			ipv6Ue_addr := ""
			if len(ipv6Ue) > 0 {
				ipv6Ue_addr = ipv6Ue[0].(string)
			}

			ipv6Cpe := metrics["Ipv6Cpe"].([]any)
			ipv6Cpe_addr := ""
			if len(ipv6Cpe) > 0 {
				ipv6Cpe_addr = ipv6Cpe[0].(string)
			}

			ch <- prometheus.MustNewConstMetric(
				e.metrics["ip_allocation"].Desc,
				e.metrics["ip_allocation"].Type,
				1.0, deviceID, deviceType, accountNumber, siteName,
				ipv4_addr, ipv6Ue_addr, ipv6Cpe_addr)
		}
	}

	ch <- prometheus.MustNewConstMetric(
		e.metrics["count"].Desc,
		e.metrics["count"].Type,
		float64(totalObjects["user_terminal"]), "user_terminal", accountNumber)

	ch <- prometheus.MustNewConstMetric(
		e.metrics["count"].Desc,
		e.metrics["count"].Type,
		float64(totalObjects["router"]), "router", accountNumber)

	ch <- prometheus.MustNewConstMetric(
		e.metrics["count"].Desc,
		e.metrics["count"].Type,
		float64(totalObjects["ip_allocation"]), "ip_allocation", accountNumber)

	return totalObjects, nil
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) (up float64) {
	e.totalScrapes.Inc()

	token, err := e.fetchToken()
	if err != nil {
		level.Error(e.logger).Log("msg", "Error fetching token", "err", err)
		return 0
	}

	objectTotalAllAccounts := map[string]int{
		"user_terminal": 0,
		"router":        0,
		"ip_allocation": 0,
	}

	for _, accountNumber := range e.accountNumbers {
		objectTotal, err := e.gatherMetrics(ch, token, accountNumber)
		if err != nil {
			level.Error(e.logger).Log("msg", "Error gathering metrics", "err", err)
			return 0
		}

		objectTotalAllAccounts["user_terminal"] += objectTotal["user_terminal"]
		objectTotalAllAccounts["router"] += objectTotal["router"]
		objectTotalAllAccounts["ip_allocation"] += objectTotal["ip_allocation"]
	}

	ch <- prometheus.MustNewConstMetric(
		e.metrics["count"].Desc,
		e.metrics["count"].Type,
		float64(objectTotalAllAccounts["user_terminal"]), "user_terminal", "all")

	ch <- prometheus.MustNewConstMetric(
		e.metrics["count"].Desc,
		e.metrics["count"].Type,
		float64(objectTotalAllAccounts["router"]), "router", "all")

	ch <- prometheus.MustNewConstMetric(
		e.metrics["count"].Desc,
		e.metrics["count"].Type,
		float64(objectTotalAllAccounts["ip_allocation"]), "ip_allocation", "all")

	return 1
}

// Maps metric names to values
func mapMetrics(values []any, metricEnum []string) map[string]any {
	metricMap := make(map[string]any)
	for i := range metricEnum {
		metricMap[metricEnum[i]] = values[i]
	}
	return metricMap
}

// Convert alert ids to descriptive names
func alertsToStrings(alerts []any) []string {
	alertStrings := make([]string, len(alerts))
	for _, item := range alerts {
		value := strconv.FormatFloat(item.(float64), 'f', -1, 64)
		alertStrings = append(alertStrings, value)
	}
	return alertStrings
}

// Map user terminals to site names obtained from service lines nickname field
func mapUserTerminalNames(serviceLines []ServiceLine, userTerminals []UserTerminal) map[string]string {
	serviceLineMap := make(map[string]string)
	userTerminalMap := make(map[string]string)
	for i := range serviceLines {
		serviceLineMap[serviceLines[i].ServiceLineNumber] = serviceLines[i].Nickname
	}
	for i := range userTerminals {
		userTerminalMap["ut"+userTerminals[i].UserTerminalID] = serviceLineMap[userTerminals[i].ServiceLineNumber]
	}
	return userTerminalMap
}

func main() {
	var (
		webConfig        = webflag.AddFlags(kingpin.CommandLine, ":9350")
		metricsPath      = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		scrapeURI        = kingpin.Flag("starlink.scrape-uri", "URI on which to scrape starlink.").Default("https://web-api.starlink.com").String()
		authURI          = kingpin.Flag("starlink.auth-uri", "URI on which to request authentication token.").Default("https://www.starlink.com/api/auth/connect/token").String()
		sslVerify        = kingpin.Flag("http.ssl-verify", "Flag that enables SSL certificate verification for the scrape URI").Default("true").Bool()
		timeout          = kingpin.Flag("http.timeout", "Timeout for trying to get stats from starlink.").Default("30s").Duration()
		httpProxyFromEnv = kingpin.Flag("http.proxy-from-env", "Flag that enables using HTTP proxy settings from environment variables ($http_proxy, $https_proxy, $no_proxy)").Default("false").Bool()
		clientID         = kingpin.Flag("starlink.client-id", "Client ID for starlink API.").Required().String()
		clientSecret     = kingpin.Flag("starlink.client-secret", "Client secret for the starlink API.").Required().String()
		accountNumbers   = kingpin.Flag("starlink.account-number", "Account number for the starlink API.").Required().String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("starlink_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting starlink_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())

	exporter, err := NewExporter(*scrapeURI, *authURI, *clientID, *clientSecret, *accountNumbers, *sslVerify, *httpProxyFromEnv, *timeout, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating an exporter", "err", err)
		os.Exit(1)
	}
	prometheus.MustRegister(exporter)
	prometheus.MustRegister(version.NewCollector("starlink_exporter"))

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Starlink Exporter</title></head>
             <body>
             <h1>Starlink Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	srv := &http.Server{}
	if err := web.ListenAndServe(srv, webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
