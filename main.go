package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
)

func sendQuery(ip, domainName string, recordType uint16) (DNSPacket, error) {
	query := buildQuery(domainName, recordType)
	conn, err := net.Dial("udp", ip+":53")
	if err != nil {
		return DNSPacket{}, fmt.Errorf("cannot connect to DNS: %w", err)
	}
	defer conn.Close()
	_, err = conn.Write(query)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("cannot write to connection: %w", err)
	}
	p := make([]byte, 1024)
	n, err := bufio.NewReader(conn).Read(p)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("cannot read from connection: %w", err)
	}
	packet, err := parseDNSPacket(p[:n])
	if err != nil {
		return DNSPacket{}, fmt.Errorf("cannot parse DNSPacket: %w", err)
	}
	return packet, nil
}

func getAnswer(packet DNSPacket) []byte {
	for _, a := range packet.answers {
		if a.type_ == TYPE_A {
			return a.data
		}
	}
	return nil
}

func getNameserverIp(packet DNSPacket) []byte {
	for _, a := range packet.additionals {
		if a.type_ == TYPE_A {
			return a.data
		}
	}
	return nil
}

func getNameserver(packet DNSPacket) string {
	for _, a := range packet.authorities {
		if a.type_ == TYPE_NS {
			return string(a.data)
		}
	}
	return ""
}

func resolve(domainName string, recordType uint16) ([]byte, error) {
	nameserver := "198.41.0.4"
	for {
		log.Printf("Querying %s for %s\n", nameserver, domainName)
		packet, err := sendQuery(nameserver, domainName, recordType)
		if err != nil {
			return nil, fmt.Errorf("error when sending query: %w", err)
		}
		if ip := getAnswer(packet); ip != nil {
			return ip, nil
		} else if nsIP := getNameserverIp(packet); nsIP != nil {
			nameserver = string(nsIP)
		} else if nsDomain := getNameserver(packet); nsDomain != "" {
			if b, err := resolve(nsDomain, TYPE_A); err != nil {
				return nil, fmt.Errorf("could not resolve domain name: %w", err)
			} else {
				nameserver = string(b)
			}
		} else {
			return nil, fmt.Errorf("no ip or nameserver in %v", packet)
		}
	}
}
func main() {
	ip, err := resolve("twitter.com", TYPE_A)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s", string(ip))
}
