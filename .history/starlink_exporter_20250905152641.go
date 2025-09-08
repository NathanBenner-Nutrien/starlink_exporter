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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
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
		"downlink_throughput_mbps":       newMetric("downlink_throughput_mbps", "Downlink throughput in Mbps.", prometheus.GaugeValue, []string{"device_id", "device_type"}, nil),
		"uplink_throughput_mbps":         newMetric("uplink_throughput_mbps", "Uplink throughput in Mbps.", prometheus.GaugeValue, []string{"device_id", "device_type"}, nil),
		"ping_drop_rate":                 newMetric("ping_drop_rate", "Ping drop rate.", prometheus.GaugeValue, []string{"device_id", "device_type"}, nil),
		"ping_latency_ms":                newMetric("ping_latency_ms", "Ping latency in milliseconds.", prometheus.GaugeValue, []string{"device_id", "device_type"}, nil),
		"uptime_seconds":                 newMetric("uptime_seconds", "Device uptime in seconds.", prometheus.GaugeValue, []string{"device_id", "device_type"}, nil),
		"wifi_uptime_seconds":            newMetric("wifi_uptime_seconds", "WiFi uptime in seconds.", prometheus.GaugeValue, []string{"device_id", "device_type"}, nil),
		"active_alerts":                  newMetric("active_alerts", "Active alerts status.", prometheus.GaugeValue, []string{"device_id", "device_type", "alert_type"}, nil),
	}

	starlinkUp = prometheus.NewDesc(prometheus.BuildFQName("starlink", "", "up"), "Was the last scrape of starlink successful.", nil, nil)
)

// Exporter collects stats from the given URI and exports them using
// the prometheus metrics package.
type Exporter struct {
	URI          string
	id           string
	secret       string
	sslVerify    bool
	proxyFromEnv bool
	timeout      time.Duration
	mutex        sync.RWMutex
	up           prometheus.Gauge
	totalScrapes prometheus.Counter
	metrics      metricTypes
	logger       log.Logger
}

// NewExporter returns an initialized Exporter.
func NewExporter(uri string, id string, secret string, sslVerify, proxyFromEnv bool, timeout time.Duration, logger log.Logger) (*Exporter, error) {
	return &Exporter{
		URI:          uri,
		id:           id,
		secret:       secret,
		sslVerify:    sslVerify,
		proxyFromEnv: proxyFromEnv,
		timeout:      timeout,
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
type Token struct {
	Token     string `json:"access_token"`
	Expiry    int    `json:"expires_in"`
	TokenType string `json:"token_type"`
	Scope     string `json:"scope"`
}

type Telemetry struct {
	Data     TelemetryData     `json:"data"`
	MetaData TelemetryMetadata `json:"metadata"`
}

type TelemetryData struct {
	Values  [][]interface{} `json:"values"`
	Columns ColumnsType     `json:"columnNamesByDeviceType"`
}

type ColumnsType struct {
	UserTerminal          []string `json:"u"`
	Router                []string `json:"r"`
	UserTerminalDataUsage []string `json:"d"`
	IpAllocs              []string `json:"i"`
}

type TelemetryMetadata struct {
	Enumerators Enumerator `json:"enums"`
}

type Enumerator struct {
	DeviceType         map[string]string            `json:"DeviceType"`
	AlertsByDeviceType map[string]map[string]string `json:"AlertsByDeviceType"`
}

// Fetch authentication token from Starlink
func fetchToken(id string, secret string, sslVerify bool, proxyFromEnv bool, timeout time.Duration) (string, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !sslVerify}}
	if proxyFromEnv {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
	}

	requestBody := url.Values{}
	requestBody.Set("client_id", id)
	requestBody.Set("client_secret", secret)
	requestBody.Set("grant_type", "client_credentials")

	req, err := http.NewRequest("POST", "https://www.starlink.com/api/auth/connect/token", strings.NewReader(requestBody.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %s", err)
	}

	if !(response.StatusCode >= 200 && response.StatusCode < 300) {
		return "", fmt.Errorf("HTTP status %d: %s", response.StatusCode, string(body))
	}

	var data Token
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("error parsing response: %s", err)
	}

	return data.Token, nil
}

func parseValue(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", value)
	}
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) (up float64) {
	e.totalScrapes.Inc()

	token, err := fetchToken(e.id, e.secret, e.sslVerify, e.proxyFromEnv, e.timeout)
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

	// Query the telemetry data
	req, err := http.NewRequest("POST", "https://web-api.starlink.com/telemetry/stream/v1/telemetry", nil)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error creating request", "err", err)
		return 0
	}

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")

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

	var data Telemetry
	body, err := io.ReadAll(response.Body)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error reading response body", "err", err)
		return 0
	}
	if err := json.Unmarshal(body, &data); err != nil {
		level.Error(e.logger).Log("msg", "Error unmarshaling response body", "err", err)
		return 0
	}

	// Process telemetry values
	for _, values := range data.Data.Values {
		if len(values) == 0 {
			continue
		}

		deviceType, ok := values[0].(string)
		if !ok {
			continue
		}

		switch deviceType {
		case "u": // User Terminal
			e.processUserTerminal(ch, values, data.Data.Columns.UserTerminal, data.MetaData.Enumerators.AlertsByDeviceType["u"])
		case "r": // Router
			e.processRouter(ch, values, data.Data.Columns.Router, data.MetaData.Enumerators.AlertsByDeviceType["r"])
		}
	}

	return 1
}

func (e *Exporter) processUserTerminal(ch chan<- prometheus.Metric, values []interface{}, columns []string, alerts map[string]string) {
	if len(values) < len(columns) {
		level.Warn(e.logger).Log("msg", "User terminal data has fewer values than expected columns")
		return
	}

	deviceID := ""
	if len(values) > 2 {
		if id, ok := values[2].(string); ok {
			deviceID = id
		}
	}

	deviceType := "user_terminal"

	// Map column indices
	columnMap := make(map[string]int)
	for i, col := range columns {
		columnMap[col] = i
	}

	// Extract throughput metrics (speeds)
	if idx, ok := columnMap["DownlinkThroughput"]; ok && len(values) > idx {
		if val, err := parseValue(values[idx]); err == nil {
			ch <- prometheus.MustNewConstMetric(e.metrics["downlink_throughput_mbps"].Desc, e.metrics["downlink_throughput_mbps"].Type, val, deviceID, deviceType)
		}
	}

	if idx, ok := columnMap["UplinkThroughput"]; ok && len(values) > idx {
		if val, err := parseValue(values[idx]); err == nil {
			ch <- prometheus.MustNewConstMetric(e.metrics["uplink_throughput_mbps"].Desc, e.metrics["uplink_throughput_mbps"].Type, val, deviceID, deviceType)
		}
	}

	// Extract ping metrics
	if idx, ok := columnMap["PingDropRateAvg"]; ok && len(values) > idx {
		if val, err := parseValue(values[idx]); err == nil {
			ch <- prometheus.MustNewConstMetric(e.metrics["ping_drop_rate"].Desc, e.metrics["ping_drop_rate"].Type, val, deviceID, deviceType)
		}
	}

	if idx, ok := columnMap["PingLatencyMsAvg"]; ok && len(values) > idx {
		if val, err := parseValue(values[idx]); err == nil {
			ch <- prometheus.MustNewConstMetric(e.metrics["ping_latency_ms"].Desc, e.metrics["ping_latency_ms"].Type, val, deviceID, deviceType)
		}
	}

	// Extract uptime metric
	if idx, ok := columnMap["Uptime"]; ok && len(values) > idx {
		if val, err := parseValue(values[idx]); err == nil {
			ch <- prometheus.MustNewConstMetric(e.metrics["uptime_seconds"].Desc, e.metrics["uptime_seconds"].Type, val, deviceID, deviceType)
		}
	}

	// Process active alerts
	if idx, ok := columnMap["ActiveAlerts"]; ok && len(values) > idx {
		if alertSlice, ok := values[idx].([]interface{}); ok {
			for _, alertInterface := range alertSlice {
				if alertCode, ok := alertInterface.(float64); ok {
					alertCodeStr := strconv.Itoa(int(alertCode))
					alertType := alertCodeStr
					if alertName, exists := alerts[alertCodeStr]; exists {
						alertType = alertName
					}
					ch <- prometheus.MustNewConstMetric(e.metrics["active_alerts"].Desc, e.metrics["active_alerts"].Type, 1, deviceID, deviceType, alertType)
				}
			}
		}
	}
}

func (e *Exporter) processRouter(ch chan<- prometheus.Metric, values []interface{}, columns []string, alerts map[string]string) {
	if len(values) < len(columns) {
		level.Warn(e.logger).Log("msg", "Router data has fewer values than expected columns")
		return
	}

	deviceID := ""
	if len(values) > 2 {
		if id, ok := values[2].(string); ok {
			deviceID = id
		}
	}

	deviceType := "router"

	// Map column indices
	columnMap := make(map[string]int)
	for i, col := range columns {
		columnMap[col] = i
	}

	// Extract WiFi uptime metric
	if idx, ok := columnMap["WifiUptimeS"]; ok && len(values) > idx {
		if val, err := parseValue(values[idx]); err == nil {
			ch <- prometheus.MustNewConstMetric(e.metrics["wifi_uptime_seconds"].Desc, e.metrics["wifi_uptime_seconds"].Type, val, deviceID, deviceType)
		}
	}

	// Extract ping metrics
	if idx, ok := columnMap["InternetPingDropRate"]; ok && len(values) > idx {
		if val, err := parseValue(values[idx]); err == nil {
			ch <- prometheus.MustNewConstMetric(e.metrics["ping_drop_rate"].Desc, e.metrics["ping_drop_rate"].Type, val, deviceID, deviceType)
		}
	}

	if idx, ok := columnMap["InternetPingLatencyMs"]; ok && len(values) > idx {
		if val, err := parseValue(values[idx]); err == nil {
			ch <- prometheus.MustNewConstMetric(e.metrics["ping_latency_ms"].Desc, e.metrics["ping_latency_ms"].Type, val, deviceID, deviceType)
		}
	}

	// Process active alerts
	if idx, ok := columnMap["ActiveAlerts"]; ok && len(values) > idx {
		if alertSlice, ok := values[idx].([]interface{}); ok {
			for _, alertInterface := range alertSlice {
				if alertCode, ok := alertInterface.(float64); ok {
					alertCodeStr := strconv.Itoa(int(alertCode))
					alertType := alertCodeStr
					if alertName, exists := alerts[alertCodeStr]; exists {
						alertType = alertName
					}
					ch <- prometheus.MustNewConstMetric(e.metrics["active_alerts"].Desc, e.metrics["active_alerts"].Type, 1, deviceID, deviceType, alertType)
				}
			}
		}
	}
}

func main() {
	var (
		webConfig        = webflag.AddFlags(kingpin.CommandLine, ":9350")
		metricsPath      = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		scrapeURI        = kingpin.Flag("starlink.scrape-uri", "URI on which to scrape starlink.").Default("https://web-api.starlink.com/enterprise/").String()
		sslVerify        = kingpin.Flag("starlink.ssl-verify", "Flag that enables SSL certificate verification for the scrape URI").Default("true").Bool()
		timeout          = kingpin.Flag("starlink.timeout", "Timeout for trying to get stats from starlink.").Default("30s").Duration()
		httpProxyFromEnv = kingpin.Flag("http.proxy-from-env", "Flag that enables using HTTP proxy settings from environment variables ($http_proxy, $https_proxy, $no_proxy)").Default("false").Bool()
		clientID         = kingpin.Flag("starlink.client-id", "Client ID for starlink API.").Required().String()
		clientSecret     = kingpin.Flag("starlink.client-secret", "Client secret for the starlink API.").Required().String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("starlink_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting starlink_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())

	exporter, err := NewExporter(*scrapeURI, *clientID, *clientSecret, *sslVerify, *httpProxyFromEnv, *timeout, logger)
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