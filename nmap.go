package main

import (
    "encoding/csv"
    "encoding/json"
    "fmt"
    "os"
    "math"
    "strings"
    "time"
    "log"
    "io"
    "github.com/Ullaakut/nmap"
)

func main() {
    // Start the scan clock
    start:= time.Now()

    // Setup log file
    logfile, err := os.OpenFile("scan.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer logfile.Close()
    mw := io.MultiWriter(os.Stdout, logfile)
    log.SetOutput(mw)

    // Open the CSV file
    file, err := os.Open("ips.csv")
    if err != nil {
        log.Fatalf("Failure to open CSV: %v", err)
        return
    }
    defer file.Close()

    // Read the CSV file
    reader := csv.NewReader(file)
    records, err := reader.ReadAll()
    if err != nil {
        log.Println(err)
        return
    }

    // Loop through the records and scan each IP address
    for _, record := range records {      
        // Create a new Nmap scan
        scan, _ := nmap.NewScanner(
            nmap.WithTargets(record[0]),
            nmap.WithPorts("1-65535"),
            nmap.WithServiceInfo(),
        )

        // Run the scan
        result, warning, err := scan.Run()

        if err != nil {
            log.Fatalf("Failed to run scan: %v", err)
            continue
        }
        if warning != nil {
            log.Printf("Warnings: \n %v", warning)
        }

        // Get output JSON
        jsonOutput, _ := json.MarshalIndent(result, "", "  ")
        elapsed := math.Round(time.Since(start).Minutes())
        ip := strings.Replace(record[0], "/", "-", -1)

        log.Printf("Scan on %s took %.0f minutes\n", record[0], elapsed)

        // Write to a file
        fileName := fmt.Sprintf("%s-results.json", ip)
        f, _ := os.Create(fileName)
        if err != nil {
            log.Fatalf("Failed to create results: %v", err)
            return
        }
        defer f.Close()
        f.Write(jsonOutput)
    }
}