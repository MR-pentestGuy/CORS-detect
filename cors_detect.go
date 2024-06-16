package main

import (
    "bufio"
    "flag"
    "fmt"
    "net/http"
    "os"
)

// go run cors_detect.go -l urls.txt -c "your_cookie_here"
// CheckCORSVulnerability checks if the given URL is vulnerable to CORS misconfiguration
func CheckCORSVulnerability(targetURL, cookie string) bool {
    origins := []string{
        "https://example.com",
        "http://malicious-site.com",
        "http://localhost:8000", // You can add more origins if needed
    }

    vulnerable := false
    for _, origin := range origins {
        req, err := http.NewRequest("GET", targetURL, nil)
        if err != nil {
            fmt.Printf("Error creating request to %s: %s\n", targetURL, err)
            continue
        }

        req.Header.Set("Origin", origin)
        req.Header.Set("Cookie", cookie)

        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
            fmt.Printf("Error making request to %s: %s\n", targetURL, err)
            continue
        }
        defer resp.Body.Close()

        if resp.Header.Get("Access-Control-Allow-Origin") == origin || resp.Header.Get("Access-Control-Allow-Origin") == "*" {
            vulnerable = true
            fmt.Printf("CORS vulnerability detected at %s with origin %s\n", targetURL, origin)
            break
        }
    }

    return vulnerable
}

func main() {
    // Define the flags for the list of URLs and the cookie
    urlList := flag.String("l", "", "Path to the list of URLs")
    cookie := flag.String("c", "", "Cookie to include in the requests")
    flag.Parse()

    // Open the file with the list of URLs
    file, err := os.Open(*urlList)
    if err != nil {
        fmt.Printf("Error opening file: %s\n", err)
        return
    }
    defer file.Close()

    // Read the URLs line by line
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        url := scanner.Text()
        if CheckCORSVulnerability(url, *cookie) {
            fmt.Printf("URL %s is VULNERABLE to CORS\n", url)
        } else {
            fmt.Printf("URL %s is not vulnerable to CORS misconfiguration\n", url)
        }
    }

    if err := scanner.Err(); err != nil {
        fmt.Printf("Error reading file: %s\n", err)
    }
}
