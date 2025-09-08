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
		"devicesTotal":       newMetric("device_total", "Number of devices reported to CrowdStrike.", prometheus.GaugeValue, nil, nil),
		"devicesReported24h": newMetric("device_reported_24h", "Number of devices reported to CrowdStrike in last 24 hours.", prometheus.GaugeValue, nil, nil),
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
	Values  []string    `json:"values"`
	Columns ColumnsType `json:"columnNamesByDeviceType"`
}

type ColumnsType struct {
	UserTerminal []string `'json:"u"`
	Router	   []string `'json:"r"`
	UserTerminalDataUsage []string `'json:"d"`
	IpAllocs	  []string `'json:"i"`
}

type TelemetryMetadata struct {
	Enumerators Enumerator `json:"enums"`
}

type Enumerator struct {
	DeviceType map[string]string `json:"DeviceType"`
	Alerts map[string]string `json:"AlertsByDeviceType"`
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

	request_body := url.Values{}
	request_body.Set("client_id", id)
	request_body.Set("client_secret", secret)
	req, err := http.NewRequest("POST", "https://www.starlink.com/api/auth/connect/token", strings.NewReader(request_body.Encode()))
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

	var data Token
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

	request_body := url.Values{}
	request_body.Set("limit", "10")
	request_body.Set("offset", "0")

	// Query the total number of devices reported
	req, err := http.NewRequest("GET", "https://api.crowdstrike.com/devices/queries/devices/v1", strings.NewReader(request_body.Encode()))
	if err != nil {
		level.Error(e.logger).Log("msg", "Error creating request", "err", err)
		return 0
	}

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	response, err := client.Do(req)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error fetching devices", "err", err)
		return 0
	}
	defer response.Body.Close()
	if !(response.StatusCode >= 200 && response.StatusCode < 300) {
		level.Error(e.logger).Log("msg", "Error fetching devices", "err", err)
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

	// Report on metrics
	// "DeviceType",
	// "UtcTimestampNs",
	// "DeviceId",
	// ==> "WifiUptimeS", (r)
	// "WifiSoftwareVersion",
	// "WifiHardwareVersion",
	// "WifiIsRepeater",
	// "WifiHopsFromController",
	// "WifiIsBypassed",
	// ==> "InternetPingDropRate", (u)
	// ==> "InternetPingLatencyMs", (u)
	// "WifiPopPingDropRate",
	// "WifiPopPingLatencyMs",
	// "DishPingDropRate",
	// "DishPingLatencyMs",
	// ==> "ActiveAlerts" (r)
	ch <- prometheus.MustNewConstMetric(e.metrics["devicesTotal"].Desc, e.metrics["devicesTotal"].Type, float64(data.Data.Values["u"].Total))

	return 1
}

func main() {

	var (
		webConfig        = webflag.AddFlags(kingpin.CommandLine, ":9350")
		metricsPath      = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		scrapeURI        = kingpin.Flag("starlink.scrape-uri", "URI on which to scrape starlink.").Default("https://api.crowdstrike.com/api/v1/").String()
		sslVerify        = kingpin.Flag("starlink.ssl-verify", "Flag that enables SSL certificate verification for the scrape URI").Default("true").Bool()
		timeout          = kingpin.Flag("starlink.timeout", "Timeout for trying to get stats from starlink.").Default("5s").Duration()
		httpProxyFromEnv = kingpin.Flag("http.proxy-from-env", "Flag that enables using HTTP proxy settings from environment variables ($http_proxy, $https_proxy, $no_proxy)").Default("false").Bool()
		token            = kingpin.Flag("starlink.id", "Client ID for starlink API.").String()
		org              = kingpin.Flag("starlink.secret", "Client secret for the starlink API.").String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("starlink_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting starlink_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())

	exporter, err := NewExporter(*scrapeURI, *token, *org, *sslVerify, *httpProxyFromEnv, *timeout, logger)
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
