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
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
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
			[]string{"type"}, nil),

		"routers_total": newMetric(
			"routers_total",
			"Total number of routers.",
			prometheus.GaugeValue, nil, nil),

		"ip_allocations_total": newMetric(
			"ip_allocations_total",
			"Total number of IP allocations.",
			prometheus.GaugeValue, nil, nil),

		"downlink_throughput": newMetric(
			"downlink_throughput",
			"Downlink throughput in Mbps.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type"}, nil),

		"uplink_throughput": newMetric(
			"uplink_throughput",
			"Uplink throughput in Mbps.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type"}, nil),

		"ping_drop_rate": newMetric(
			"ping_drop_rate",
			"Average ping drop rate.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type"}, nil),

		"ping_latency": newMetric(
			"ping_latency",
			"Average ping latency in milliseconds.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type"}, nil),

		"obstruction_percent_time": newMetric(
			"obstruction_percent_time",
			"Obstruction percentage time.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type"}, nil),

		"uptime": newMetric(
			"uptime",
			"Device uptime in seconds.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type"}, nil),

		"signal_quality": newMetric(
			"signal_quality",
			"Signal quality.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type"}, nil),

		"wifi_uptime": newMetric(
			"wifi_uptime",
			"Wifi uptime in seconds.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type"}, nil),

		"wifi_clients_total": newMetric(
			"wifi_clients_total",
			"Total number of WiFi clients.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type"}, nil),

		"active_alerts": newMetric(
			"active_alerts",
			"Number of active alerts.",
			prometheus.GaugeValue,
			[]string{"device_id", "device_type", "alert_type"}, nil),
	}

	starlinkUp = prometheus.NewDesc(prometheus.BuildFQName("starlink", "", "up"), "Was the last scrape of starlink successful.", nil, nil)
)

// Exporter collects stats from the given URI and exports them using
// the prometheus metrics package.
type Exporter struct {
	URI           string
	authUri       string
	id            string
	secret        string
	accountNumber string
	sslVerify     bool
	proxyFromEnv  bool
	timeout       time.Duration
	mutex         sync.RWMutex
	up            prometheus.Gauge
	totalScrapes  prometheus.Counter
	metrics       metricTypes
	logger        log.Logger
}

// NewExporter returns an initialized Exporter.
func NewExporter(uri string, authUri string, id string, secret string, accountNumber string, sslVerify bool, proxyFromEnv bool, timeout time.Duration, logger log.Logger) (*Exporter, error) {
	return &Exporter{
		URI:           uri,
		authUri:       authUri,
		id:            id,
		secret:        secret,
		accountNumber: accountNumber,
		sslVerify:     sslVerify,
		proxyFromEnv:  proxyFromEnv,
		timeout:       timeout,
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

// Fetch authentication token from Starlink
func (e *Exporter) fetchToken() (string, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !e.sslVerify}}
	if e.proxyFromEnv {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := http.Client{
		Timeout:   e.timeout,
		Transport: tr,
	}

	requestBody := url.Values{}
	requestBody.Set("client_id", e.id)
	requestBody.Set("client_secret", e.secret)
	requestBody.Set("grant_type", "client_credentials")

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

func (e *Exporter) scrape(ch chan<- prometheus.Metric) (up float64) {
	e.totalScrapes.Inc()

	token, err := e.fetchToken()
	if err != nil {
		level.Error(e.logger).Log("msg", "Error fetching token", "err", err)
		return 0
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !e.sslVerify}}
	if e.proxyFromEnv {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := http.Client{
		Timeout:   e.timeout,
		Transport: tr,
	}

	requestBody := TelemetryRequestBody{AccountNumber: e.accountNumber}
	jsonRequestBody, err := json.Marshal(requestBody)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error marshalling JSON %v", err)
	}

	req, err := http.NewRequest("POST", e.URI, bytes.NewBuffer(jsonRequestBody))
	if err != nil {
		level.Error(e.logger).Log("msg", "Error creating request", "err", err)
		return 0
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	response, err := client.Do(req)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error fetching telemetry", "err", err)
		return 0
	}
	defer response.Body.Close()

	if !(response.StatusCode >= 200 && response.StatusCode < 300) {
		level.Error(e.logger).Log("msg", "Error fetching telemetry", "status", response.StatusCode)
		return 0
	}

	var telemetryResponse TelemetryResponse
	body, err := io.ReadAll(response.Body)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error reading response body", "err", err)
		return 0
	}
	if err := json.Unmarshal(body, &telemetryResponse); err != nil {
		level.Error(e.logger).Log("msg", "Error unmarshaling response body", "err", err)
		return 0
	}

	userTerminalCount := 0
	routerCount := 0
	ipAllocCount := 0

	processedDevices := make(map[string]bool)

	for _, values := range telemetryResponse.Data.Values {
		if len(values) == 0 {
			continue
		}

		deviceType := values[0].(string)

		metrics := mapMetrics(values, telemetryResponse.Data.Columns[deviceType])

		switch deviceType {
		case "u": // User Terminal
			deviceType := "user_terminal"
			deviceID := metrics["DeviceId"].(string)

			// Handle duplicate device IDs
			_, keyExists := processedDevices[deviceID]
			if keyExists {
				continue
			} else {
				processedDevices[deviceID] = true
			}

			userTerminalCount++

			ch <- prometheus.MustNewConstMetric(
				e.metrics["downlink_throughput"].Desc,
				e.metrics["downlink_throughput"].Type,
				metrics["DownlinkThroughput"].(float64), deviceID, deviceType)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["uplink_throughput"].Desc,
				e.metrics["uplink_throughput"].Type,
				metrics["UplinkThroughput"].(float64), deviceID, deviceType)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["ping_drop_rate"].Desc,
				e.metrics["ping_drop_rate"].Type,
				metrics["PingDropRateAvg"].(float64), deviceID, deviceType)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["ping_latency"].Desc,
				e.metrics["ping_latency"].Type,
				metrics["PingLatencyMsAvg"].(float64), deviceID, deviceType)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["obstruction_percent_time"].Desc,
				e.metrics["obstruction_percent_time"].Type,
				metrics["ObstructionPercentTime"].(float64), deviceID, deviceType)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["uptime"].Desc,
				e.metrics["uptime"].Type,
				metrics["Uptime"].(float64), deviceID, deviceType)

			ch <- prometheus.MustNewConstMetric(
				e.metrics["signal_quality"].Desc,
				e.metrics["signal_quality"].Type,
				metrics["SignalQuality"].(float64), deviceID, deviceType)

			// alertCount := len(metrics["ActiveAlerts"].([]string))
			// alerts := metrics["ActiveAlerts"].([]string)
			// for _, alert := range alerts {
			// 	// Handle alerts
			// }

		case "r": // Router
			deviceType := "router"
			deviceID := metrics["DeviceId"].(string)

			// Handle duplicate device IDs
			_, keyExists := processedDevices[deviceID]
			if keyExists {
				continue
			} else {
				processedDevices[deviceID] = true
			}

			routerCount++

			ch <- prometheus.MustNewConstMetric(
				e.metrics["wifi_uptime"].Desc,
				e.metrics["wifi_uptime"].Type,
				metrics["WifiUptimeS"].(float64), deviceID, deviceType)

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["ping_drop_rate"].Desc,
			// 	e.metrics["ping_drop_rate"].Type,
			// 	metrics["InternetPingDropRate"].(float64), deviceID, deviceType)

			// ch <- prometheus.MustNewConstMetric(
			// 	e.metrics["ping_latency"].Desc,
			// 	e.metrics["ping_latency"].Type,
			// 	metrics["InternetPingLatencyMs"].(float64), deviceID, deviceType)

		case "i": // IP Allocation
			ipAllocCount++
		}
	}

	ch <- prometheus.MustNewConstMetric(
		e.metrics["count"].Desc,
		e.metrics["count"].Type,
		float64(userTerminalCount), "user_terminal")

	ch <- prometheus.MustNewConstMetric(
		e.metrics["count"].Desc,
		e.metrics["count"].Type,
		float64(routerCount), "router")

	ch <- prometheus.MustNewConstMetric(
		e.metrics["count"].Desc,
		e.metrics["count"].Type,
		float64(ipAllocCount), "ip_allocation")

	return 1
}

// Maps metric names to values
func mapMetrics(values []any, metricEnum []string) (metrics map[string]any) {
	metricMap := make(map[string]any)
	for i := range metricEnum {
		metricMap[metricEnum[i]] = values[i]
	}
	return metricMap
}

func main() {
	var (
		webConfig        = webflag.AddFlags(kingpin.CommandLine, ":9350")
		metricsPath      = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		scrapeURI        = kingpin.Flag("starlink.scrape-uri", "URI on which to scrape starlink.").Default("https://web-api.starlink.com/telemetry/stream/v1/telemetry").String()
		authURI          = kingpin.Flag("starlink.auth-uri", "URI on which to request authentication token.").Default("https://www.starlink.com/api/auth/connect/token").String()
		sslVerify        = kingpin.Flag("http.ssl-verify", "Flag that enables SSL certificate verification for the scrape URI").Default("true").Bool()
		timeout          = kingpin.Flag("http.timeout", "Timeout for trying to get stats from starlink.").Default("30s").Duration()
		httpProxyFromEnv = kingpin.Flag("http.proxy-from-env", "Flag that enables using HTTP proxy settings from environment variables ($http_proxy, $https_proxy, $no_proxy)").Default("false").Bool()
		clientID         = kingpin.Flag("starlink.client-id", "Client ID for starlink API.").Required().String()
		clientSecret     = kingpin.Flag("starlink.client-secret", "Client secret for the starlink API.").Required().String()
		accountNumber    = kingpin.Flag("starlink.account-number", "Account number for the starlink API.").Required().String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("starlink_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting starlink_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())

	exporter, err := NewExporter(*scrapeURI, *authURI, *clientID, *clientSecret, *accountNumber, *sslVerify, *httpProxyFromEnv, *timeout, logger)
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
