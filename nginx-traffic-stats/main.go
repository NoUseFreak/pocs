package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/satyrius/gonx"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	recordTime = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "nginx",
		Subsystem: "traffic_stats",
		Name:      "record_time",
	})
	requestsBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "nginx",
		Subsystem: "traffic_stats",
		Name:      "request_bytes",
	}, []string{"client_ip"})
	requestsBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "nginx",
		Subsystem: "traffic_stats",
		Name:      "request_bytes_total",
	})
	requestsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "nginx",
		Subsystem: "traffic_stats",
		Name:      "requests_count",
	}, []string{"client_ip"})
	responseBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "nginx",
		Subsystem: "traffic_stats",
		Name:      "response_bytes",
	}, []string{"client_ip"})
	responseBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "nginx",
		Subsystem: "traffic_stats",
		Name:      "response_bytes_total",
	})
	startTime = time.Now()
)

type appConfig struct {
	Filters []filter `yaml:"filters"`
}

type filter struct {
	Upstream string   `yaml:"upstream"`
	Paths    []string `yaml:"paths"`
}

func main() {
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	logrus.SetFormatter(customFormatter)

	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := rest.InClusterConfig()
	if err != nil {
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			panic(err.Error())
		}
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	viper.SetConfigName("config")         // name of config file (without extension)
	viper.SetConfigType("yaml")           // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("/etc/nts/")      // path to look for the config file in
	viper.AddConfigPath("$HOME/.appname") // call multiple times to add many search paths
	viper.AddConfigPath(".")              // optionally look for config in the working directory
	err = viper.ReadInConfig()            // Find and read the config file
	if err != nil {                       // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}

	l := NewLogHelper(clientset)

	conf := &appConfig{}
	err = viper.Unmarshal(conf)
	if err != nil {
		logrus.Fatal("Invalid filters")
	}
	l.filters = conf.Filters

	start := time.Now()
	go func() {
		for {
			logrus.WithFields(logrus.Fields{
				"request_count":  l.stats.TotalRequests,
				"response_bytes": humanize.Bytes(l.stats.TotalBytes),
				"request_bytes":  humanize.Bytes(l.stats.TotalRequestBytes),
			}).Infof("Stats global (since %s)", humanize.Time(start))
			for client, stats := range l.stats.ClientStats {
				logrus.WithFields(logrus.Fields{
					"request_count":  stats.TotalRequests,
					"response_bytes": humanize.Bytes(stats.TotalBytes),
					"request_bytes":  humanize.Bytes(stats.TotalRequestBytes),
				}).Infof("Stats %s", client)
			}

			time.Sleep(5 * time.Minute)
			fmt.Println("")
		}
	}()

	go func() {
		for {
			recordTime.Set(float64(int(time.Since(startTime).Seconds())))
			time.Sleep(1 * time.Second)
		}
	}()

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		logrus.Info("Starting metrics server on http://0.0.0.0:2112/metrics")
		http.ListenAndServe(":2112", nil)
	}()
	l.GetLogs("ingress-nginx-controller", "ingress-nginx")
}

type Stats struct {
	TotalRequests     uint64
	TotalBytes        uint64
	TotalRequestBytes uint64
	ClientStats       map[string]*Stats
	mutex             *sync.Mutex
}

func (s *Stats) AddRequest(record *gonx.Entry) {
	bytes, _ := record.IntField("body_bytes_sent")
	request_bytes, _ := record.IntField("request_length")

	s.mutex.Lock()
	s.TotalRequests += 1
	s.TotalBytes += uint64(bytes)
	s.TotalRequestBytes += uint64(request_bytes)

	ip := record.Fields()["remote_addr"]
	cs, ok := s.ClientStats[ip]
	if !ok {
		n := Stats{
			TotalRequests:     1,
			TotalBytes:        uint64(bytes),
			TotalRequestBytes: uint64(request_bytes),
		}
		s.ClientStats[ip] = &n
	} else {
		cs.TotalRequests += 1
		cs.TotalBytes += uint64(bytes)
		cs.TotalRequestBytes += uint64(request_bytes)
	}
	s.mutex.Unlock()

	requestsCount.With(prometheus.Labels{"client_ip": ip}).Inc()
	requestsBytesTotal.Add(float64(request_bytes))
	requestsBytes.With(prometheus.Labels{"client_ip": ip}).Add(float64(request_bytes))
	responseBytes.With(prometheus.Labels{"client_ip": ip}).Add(float64(bytes))
	responseBytesTotal.Add(float64(bytes))
}

func (s *Stats) String() string {
	out := "Global stats:\n"
	out += fmt.Sprintf("Total requests: %d\nTotal bytes: %d\nClient stats:\n", s.TotalRequests, s.TotalBytes)
	for client, stats := range s.ClientStats {
		out += fmt.Sprintf("Client [%s]: Total requests: %d Total bytes: %d\n", client, stats.TotalRequests, stats.TotalBytes)
	}

	return out
}

func NewLogHelper(clientset *kubernetes.Clientset) *LogHelper {
	return &LogHelper{
		clientset: clientset,
		stats: Stats{
			ClientStats: make(map[string]*Stats),
			mutex:       &sync.Mutex{},
		},
	}
}

type LogHelper struct {
	clientset *kubernetes.Clientset
	stats     Stats
	filters   []filter
}

func (l *LogHelper) GetLogs(service, namespace string) {
	stopper := make(chan struct{})
	defer close(stopper)

	// go func() {
	// 	time.Sleep(24 * time.Hour)
	// 	logrus.Warn("Stopping after 24 hours")
	// 	os.Exit(0)
	// }()

	factory := informers.NewSharedInformerFactoryWithOptions(l.clientset, 10*time.Second, informers.WithNamespace(namespace))
	podInformer := factory.Core().V1().Pods().Informer()

	defer runtime.HandleCrash()
	go factory.Start(stopper)
	if !cache.WaitForCacheSync(stopper, podInformer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			if strings.HasPrefix(pod.GetName(), service) {
				logrus.Infof("Pod added: %s", pod.Name)
				go l.getPodLogs(pod.GetName(), namespace)
			}
		},
	})

	<-stopper
}

func (l *LogHelper) getPodLogs(podName string, namespace string) error {
	format := `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_length $request_time [$proxy_upstream_name] [$proxy_alternative_upstream_name] $upstream_addr $upstream_response_length $upstream_response_time $upstream_status $req_id`

	since := int64(1)
	podLogOpts := &v1.PodLogOptions{
		Follow:       true,
		Previous:     false,
		SinceSeconds: &since,
	}
	req := l.clientset.CoreV1().Pods(namespace).GetLogs(podName, podLogOpts)
	podLogs, err := req.Stream(context.TODO())
	if err != nil {
		return err
	}
	defer podLogs.Close()

	parser := gonx.NewParser(format)
	scanner := bufio.NewScanner(podLogs)
	for scanner.Scan() {
		line := scanner.Text()
		if scanner.Err() != nil {
			logrus.Errorf("Error reading logs from pod %s: %v\n", podName, scanner.Err())
			continue
		}

		e, err := parser.ParseString(line)
		if err != nil {
			logrus.Tracef("Error parsing logs from pod %s: %v\n", podName, err)
			continue
		}

		if l.filterMatch(e) {
			l.stats.AddRequest(e)
			logrus.Tracef("[%s] %s\n", podName, line)
		}
	}

	if err != nil {
		fmt.Printf("Error reading logs from pod %s: %v\n", podName, err)
	}
	logrus.Infof("Finished reading logs from pod %s", podName)

	return nil
}

// func (l *LogHelper) AddPathFilter(path string) {
// 	l.requestReg = append(l.requestReg, regexp.MustCompile(fmt.Sprintf("^GET %s", regexp.QuoteMeta(path))))
// }

func (l *LogHelper) filterMatch(record *gonx.Entry) bool {
	fields := record.Fields()
	for _, filter := range l.filters {
		// If host is set, skip if no match
		if filter.Upstream != "" && !strings.HasPrefix(fields["proxy_upstream_name"], filter.Upstream) {
			logrus.WithFields(logrus.Fields{
				"upstream": filter.Upstream,
				"record":   fields["proxy_upstream_name"],
			}).Trace("Did not match upstream")
			continue
		}

		if len(filter.Paths) == 0 {
			return true
		}

		// Check each path
		for _, path := range filter.Paths {
			re, err := regexp.Compile(fmt.Sprintf("^[A-Z]+ %s", regexp.QuoteMeta(path)))
			if err != nil {
				logrus.Errorf("Invalid path filter: %s", path)
				continue
			}
			if re.MatchString(fields["request"]) {
				return true
			}
			logrus.WithFields(logrus.Fields{
				"path":   path,
				"record": fields["request"],
			}).Trace("Did not match path")
		}
	}

	return len(l.filters) == 0
}
