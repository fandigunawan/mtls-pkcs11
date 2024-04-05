/*
Idnaf MTLS PKCS11 Client
*/
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/ThalesIgnite/crypto11"
	"github.com/miekg/pkcs11"
	"golang.org/x/term"
)

// Check if source contains data 'find'
func contains(source []uint, find uint) bool {
	for _, v := range source {
		if v == find {
			return true
		}
	}
	return false
}


// Main function
func main() {
	var pkcsLibFile, tokenSerial, tokenPin, uri, httpMethod, userAgent, outputFile string
	
	fmt.Println("Idnaf MTLS PKCS11 HTTPS Client")

	flag.StringVar(&pkcsLibFile, "pkcs11", "", "pkcs11 library path")
	flag.StringVar(&tokenPin, "token-pin", "", "token pin, it will prompt to user if it is empty")
	flag.StringVar(&uri, "uri", "", "Target URI")
	flag.StringVar(&httpMethod, "http-method", "GET", "HTTP request method")
	flag.StringVar(&userAgent, "ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36", "User agent (optional)")
	flag.StringVar(&outputFile, "output", "", "Output to file (optional), if empty it will be printed to stdout")
	flag.Parse()

	if len(os.Args) == 1 {
		fmt.Println("Use -h to see full commands")
		os.Exit(1)
	}

	fmt.Println("Configuration:")
	fmt.Println("PKCS11 lib  : ", pkcsLibFile)
	fmt.Println("HTTP method : ", httpMethod)
	fmt.Println("URI         : ", uri)

	if _, err := os.Stat(pkcsLibFile); err != nil {
		log.Fatalln(err)
	}

	p11 := pkcs11.New(pkcsLibFile)
	err := p11.Initialize()
	if err != nil {
		p11.Finalize()
		p11.Destroy()
		log.Fatalln(err)
	}

	slots, err := p11.GetSlotList(true)
	if err != nil {
		p11.Finalize()
		p11.Destroy()
		log.Fatalln(err)
	}
	if len(slots) <= 0 {
		log.Fatalf("Slot is empty, please connect your token", nil)
	}

	var selectedSlot uint = math.MaxUint
	for _, slot := range slots {
		tokenInfo, err := p11.GetTokenInfo(slot)
		if err != nil {
			p11.Finalize()
			p11.Destroy()
			log.Fatalln(err)
		}
		if selectedSlot == math.MaxUint {
			selectedSlot = slot
		}
		fmt.Println("Slot #", slot)
		fmt.Println(" - Label         : ", tokenInfo.Label)
		fmt.Println(" - Model         : ", tokenInfo.Model)
		fmt.Println(" - Serial Number : ", tokenInfo.SerialNumber)
		fmt.Println(" - Manufacturer  : ", tokenInfo.ManufacturerID)
		fmt.Println(" - HW version    : ", tokenInfo.HardwareVersion.Major, ".", tokenInfo.HardwareVersion.Minor)
	}

	if len(slots) > 1 {
		fmt.Print("Select slot: ")
		_, err := fmt.Scanf("%d", &selectedSlot)
		if err != nil {
			p11.Finalize()
			p11.Destroy()
			log.Fatal(err)
		}
		if !contains(slots, selectedSlot) {
			log.Println("Slot selection is false", nil)
		}
	} else {
		fmt.Println("Automatically select slot: ", selectedSlot)
	}
	tokenInfo, err := p11.GetTokenInfo(selectedSlot)
	if err != nil {
		log.Fatalln(err)
	}
	tokenSerial = tokenInfo.SerialNumber
	p11.Finalize()
	p11.Destroy()

	if tokenPin == "" {
		fmt.Print("Enter PIN: ")
		bytepw, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println()
		tokenPin = string(bytepw)
	}
	config := crypto11.Config{
		Path:        pkcsLibFile,
		TokenSerial: tokenSerial,
		Pin:         tokenPin,
	}

	fmt.Println("Configuring crypto11")
	context, err := crypto11.Configure(&config)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Find all paired certificates")
	certificates, err := context.FindAllPairedCertificates()
	if err != nil {
		log.Fatalln(err)
	}

	if len(certificates) == 0 {
		log.Fatalf("No certificates found!", nil)
	}
	fmt.Println("Total certificates found: ", len(certificates))
	index := 0
	for _, cert := range certificates {
		fmt.Println(index, " ", cert.Leaf.Subject)
		fmt.Println("    Validity: ", cert.Leaf.NotBefore.Local(), " to ", cert.Leaf.NotAfter.Local())
		fmt.Println("    Serial Number: ", cert.Leaf.SerialNumber.String())
		fmt.Println("    Issuer: ", cert.Leaf.Issuer)
		index++
	}
	selectedCert := 0
	if len(certificates) > 1 {
		fmt.Print("Select certificate number: ")
		reader := bufio.NewReader(os.Stdin)
		str, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		str = strings.TrimSpace(str)
		selection, err := strconv.Atoi(str)
		if err != nil {
			log.Fatal(err)
		}

		selectedCert = selection
	}
	cert := certificates[selectedCert]
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
				Renegotiation:      tls.RenegotiateOnceAsClient,
			},
		},
	}

	req, err := http.NewRequest(httpMethod, uri, nil)
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Set("User-Agent", userAgent)

	for k, v := range req.Header {
		fmt.Println("> ", k, ":", v)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("HTTP Status code: ", resp.StatusCode)
	for k, v := range resp.Header {
		fmt.Println("< ", k, ":", v)
	}
	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		if outputFile == "" {
			bodyString := string(bodyBytes)
			fmt.Println(bodyString)
		} else {
			fmt.Println("Writing output to ", outputFile)
			err = os.WriteFile(outputFile, bodyBytes, 0644)
			if err != nil {
				log.Fatal(err)
			}
		}
		
	}
}
