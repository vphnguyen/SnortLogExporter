package main

// IMPORT =======================
import (
	"log"
	"net/http"
	"os"  
	"io/ioutil" 
	"bufio"
	"strings"
	"fmt"
	"flag"
	"math"
	"time"
	"strconv"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)
// ===============================================================================
//                                             CONST
// ===============================================================================
//======================  Const will change by config file 

//Alert file location
const alert_Path = "/var/log/snort/snort_em061350/alert" 

// Size file path 
const size_Path = "size.txt"

// Web address: this is port... 
const addr = ":4051"



/* =================================================================================================================
Host tai dia chi 192.168.112.130 --- Port 8051
Cac noi dung:
==================================================  LOG SAMPLE   ===================================================

09/14/21-02:01:13.328091 ,1,140791,0,"Co may dang ping ra Gooogle",ICMP,192.168.1.9,,8.8.8.8,,34597,,0,alert,Allow

==================================================  LOG COMPONENT ANALYSYS  ========================================

09/14/21-02:01:13.328091 ,====== 1_Time
1, ============================= 2_GroupID
140791,========================= 3_ID
0,============================== 4_
"Co may dang ping ra Gooogle",== 5_Content
ICMP,=========================== 6_Protocol
192.168.1.9,==================== 7_SrcIP
,=============================== 8_Port
8.8.8.8,======================== 9_DestIP
,=============================== 10_Port
34597,========================== 11_szPacket
,=============================== 12_
0,============================== 13_
alert,========================== 14_Specified // alert, drop, reject... (Chỉ định)
Allow=========================== 15_Real_Action // Allow , Drop

==================================================================================================================== */
type AlertSample struct {
	_Time string
	_GroupID int
	_ID int
	_4 int
	_Content string
	_Protocol string
	_SrcIP string
	_SrcPort int
	_DestIP string
	_DestPort int
	_szPacket int
	_12 string
	_13 int
	_Specified string
	_Real_Action string
}

// ===============================================================================
//                                            VAR AND CONST
// ===============================================================================


//======================  Tần số lấy mẫu 
var oscillationPeriod = flag.Duration("oscillation-period", 10*time.Minute, "The duration of the rate oscillation period.")

//======================  METRICS DEFINE 
var array_AlertSample []AlertSample
var (
	// ALL OF FILE COUNT
	alertFileCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "number_of_alerts_inFile",
			Help: "========================== TEST =================== Count the amount of Alert events in Snort Alert log file.",
		},
	)

	// Specified COUNTER  withlables (alert, drop, reject)
	specifiedCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "number_of_specified",
			Help: "========================== TEST =================== Count the number of Specified each type.",
		},
		[]string{"specified"},
	)
	// realAction COUNTER  withlables (alert, drop, reject)
	realActionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "number_of_realaction",
			Help: "========================== TEST =================== Count the number of Real Action each type.",
		},
		[]string{"realaction"},
	)


)

func init(){

	prometheus.MustRegister(alertFileCounter)
prometheus.MustRegister(specifiedCounter)
prometheus.MustRegister(realActionCounter)

}
// ===============================================================================
//                                            FUNCTIONS
// ===============================================================================
//======================  ERROE CHECK
func check(e error) {
	if e != nil {
		panic(e)
	}
}
//======================  MAIN FUNCTION
func scrapeMetrics(){
	
	// Check alert file and get size
	new_size := checkAlert_GetSize(alert_Path)
	fmt.Println("Got new size data: %d",new_size)

	// Check the "size.txt" file to read the last size of alert
	old_size := int64(0)
	old_size = checkFileSize_getvalue(size_Path,new_size)
	fmt.Println("old size data: %d",old_size)

	// OKE now we get three conditions
	// 1. new < old => Rare event ALert file deleted => Set size = 0 then read again in next if
	if new_size - old_size < 0 {
		old_size=0
	}
	// 2. new > old => WE NEED TO READ NEW LINE === NORMAL ===== 
	if new_size - old_size > 0 {
		workWithFile(alert_Path, new_size - old_size)

	}
	// 3. new = old => NOTHING TO DO
	old_size=new_size


	

	////////////================ ALREADY READ SO WE SET THE SIZE = ALERT EVENTS
	dataOfSize := []byte(fmt.Sprintf("%d", new_size))
	err := ioutil.WriteFile(size_Path, dataOfSize, 0777)
	check(err)

	
}

func workWithFile(path string, subBytes int64){
	alert_file, err := os.Open(path)
	check(err)
	defer alert_file.Close()

	scanner := bufio.NewScanner(alert_file)
	for scanner.Scan() {	// Scan line by line from sub Byte... new-old
		const nFields = 16 	// Alert have 15 fields in type sample
		fields := strings.Split(string(scanner.Bytes()),",") // Split the string by comma
		var times [5] string // We will get what we need
		for i, idx := range []int{4,6,8,13,14} {
			times[i] = fields[idx]
		}

		array_AlertSample = append(array_AlertSample, AlertSample{
			_Content: times[0],
			_SrcIP: times[1],
			_DestIP: times[2],
			_Specified: times[3],
			_Real_Action:times[4],
		})
		for _, s := range array_AlertSample {
			fmt.Printf("Noi dung: %v,\n  - Tu IP: %v, \n  - Den IP: %v, \n  - Chi dinh: %v, \n  - Ket qua: %v,\n=====================================\n",s._Content, s._SrcIP, s._DestIP, s._Specified, s._Real_Action)
		}

	}

}


func checkFileSize_getvalue(path string, new_size int64) int64{
	// Just open
	file, err := os.Open(path)
	defer file.Close()

	// Check the "size.txt" file to read the last size of alert

	if (err != nil ){ // when file NOT EXIST

		// Cannot find file  (Se nghien cuu thu gon voi flag trong OS)
		// Create file and Insert alert's size to file. Or we dont need to do that in the future
		data := []byte(fmt.Sprintf("%d", new_size))
		err := ioutil.WriteFile(path, data, 0777)
		check(err)
		log.Fatalf("IF 1 === Cannot find the file to get size : %v", err)
		return 0 // That mean read everythings

	}else{ 			  //when file EXIST
		
		// Got the file
		fmt.Println("IF 2 === We got the size.txt file")
		scanner := bufio.NewScanner(file)
		scanner.Scan() 
		old_size,_ :=strconv.ParseInt(scanner.Text(), 10, 64) // Get old size 
		return old_size 
	}
}


func checkAlert_GetSize(path string) int64{
	file_alert, err := os.Stat(alert_Path) // Os Get Status of alert file
	if err != nil {
		log.Fatalf("Alert file failed to open : %v", err)
	}

	return file_alert.Size()	// return the size now
}




// ===============================================================================
//                                            MAIN
// ===============================================================================
func main() {
	// Init with Perious 
	start := time.Now()
	oscillationFactor := func() float64 {
		return 2 + math.Sin(math.Sin(2*math.Pi*float64(time.Since(start))/float64(*oscillationPeriod)))
	}

	// LOOP with lightweight func of go 
	go func(){
		for{
			//  Scrape metrics ===== MAIN FUNCTION
			scrapeMetrics()

			//  Take sleep.............
			time.Sleep(time.Duration(100*oscillationFactor()) * time.Millisecond)
		}
	}()
	//  Handler web
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(addr, nil))
}