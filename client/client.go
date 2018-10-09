package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Flags
var (
	addr       = flag.String("listen-address", ":8080", "The address to listen on for HTTP requests.")
	server     = flag.String("server", "10.0.0.10", "The IP of the Server")
	ports      = flag.String("ports", "1232", "Ports for the applications, seperated by comma")
	packetSize = flag.Int("packet-size", 800, "Size of the packets sent")
	numConns   = flag.Int("num-conns", 4, "Number of simultaneous connection to an endpoint")
	verbose    = flag.Bool("verbose", false, "Show more output")
)

// prometheus metrics
var (
	answerTimesHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "answer_time_histogram",
		Help:    "Answer Time in Milliseconds",
		Buckets: []float64{0.0001, 0.0002, 0.0003, 0.0004, 0.0005, 0.001, 0.0015, 0.002, 0.0025, 0.003, 0.0035, 0.004, 0.0045, 0.005, 0.006, 0.007, 0.008, 0.009, 0.01, 0.011, 0.012, 0.013, 0.014, 0.015, 0.016, 0.017, 0.018, 0.019, 0.020, 0.025, 0.03, 0.035, 0.04, 0.045, 0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2, 2.5, 3, 3.5, 4, 4.5, 5, 6, 7, 8, 9, 10},
	}, []string{"port"})
	requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "requests",
		Help: "Counter for sent requests",
	}, []string{"port"})
	failedRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "failedRequests",
		Help: "Counter for failed requests",
	}, []string{"port"})
	responses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "responses",
		Help: "Counter for received responses",
	}, []string{"port"})
	failedResponses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "failedResponses",
		Help: "Counter for received responses",
	}, []string{"port"})
	timeouts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "timeouts",
		Help: "Counter for requests without an answer within the timeout timerange",
	}, []string{"port"})
	falseResponses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "falseResponses",
		Help: "Counter for Responses with the wrong content",
	}, []string{"port"})
)

func serverPrometheus() {
	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func sendRequest(conn net.Conn, payload string, expectedResult string) {
	var err error
	var n int
	var timeSend, timeRecv time.Time
	buffer := make([]byte, 2048)
	for {
		n, err = conn.Write([]byte(payload))
		timeSend = time.Now()
		requests.With(prometheus.Labels{"port": conn.RemoteAddr().String()}).Inc()
		if err != nil {
			fmt.Println(err)
			failedRequests.With(prometheus.Labels{"port": conn.RemoteAddr().String()}).Inc()
		} else if n != len(payload) {
			fmt.Println("Sent to few bytes...")
			failedRequests.With(prometheus.Labels{"port": conn.RemoteAddr().String()}).Inc()
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err = conn.Read(buffer)
		timeRecv = time.Now()
		if err != nil {
			fmt.Println(err)
			failedResponses.With(prometheus.Labels{"port": conn.RemoteAddr().String()}).Inc()
			continue
		} else if n != len(expectedResult) {
			fmt.Println("Received to few bytes...")
			falseResponses.With(prometheus.Labels{"port": conn.RemoteAddr().String()}).Inc()
			continue
		} else if string(buffer[:n]) != expectedResult {
			fmt.Printf("Result is other than expected... \"%v\" != \"%v\"\n", string(buffer), expectedResult)
			falseResponses.With(prometheus.Labels{"port": conn.RemoteAddr().String()}).Inc()
			continue
		}
		responses.With(prometheus.Labels{"port": conn.RemoteAddr().String()}).Inc()
		answerTimesHistogram.With(prometheus.Labels{"port": conn.RemoteAddr().String()}).Observe(float64(timeRecv.Sub(timeSend)) / 1000000)
	}
}

func reverseString(s string) (result string) {
	for _, v := range s {
		result = string(v) + result
	}
	return
}

func init() {
	//Register the prometheus metrics
	prometheus.MustRegister(answerTimesHistogram)
	prometheus.MustRegister(requests)
	prometheus.MustRegister(failedRequests)
	prometheus.MustRegister(responses)
	prometheus.MustRegister(failedResponses)
	prometheus.MustRegister(falseResponses)
}

func main() {
	flag.Parse()
	go serverPrometheus()

	headerSize := 42

	var data string
	for i := headerSize; i < *packetSize; i++ {
		data += strconv.Itoa(i % 10)
	}

	for _, port := range strings.Split(*ports, ",") {
		for i := 0; i < *numConns; i++ {
			connStr := *server + ":" + port
			conn, err := net.Dial("udp", connStr)
			if err != nil {
				fmt.Println(err)
			}
			defer conn.Close()
			go sendRequest(conn, data, reverseString(data))

			if *verbose {
				fmt.Printf("Connection to %v setup\n", connStr)
			}
		}
	}
	time.Sleep(time.Duration(20) * time.Minute)
}
