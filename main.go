package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

type DNSRecord struct {
	name  []byte
	type_ uint16
	class uint16
	ttl   int32
	data  []byte
}

func parseDNSHeader(r *bytes.Reader) (DNSHeader, error) {
	h := DNSHeader{}
	if err := binary.Read(r, binary.BigEndian, &h.id); err != nil {
		return h, fmt.Errorf("cannot read header id: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &h.flags); err != nil {
		return h, fmt.Errorf("cannot read header flags: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &h.numQuestions); err != nil {
		return h, fmt.Errorf("cannot read header numQuestions: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &h.numAnswers); err != nil {
		return h, fmt.Errorf("cannot read header numAnswers: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &h.numAuthorities); err != nil {
		return h, fmt.Errorf("cannot read header numAuthorities: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &h.numAdditionals); err != nil {
		return h, fmt.Errorf("cannot read header numAdditionals: %w", err)
	}
	return h, nil
}

func parseQuestion(r *bytes.Reader) (DNSQuestion, error) {
	q := DNSQuestion{}
	var err error
	q.name, err = decodeName(r)
	if err != nil {
		return q, fmt.Errorf("cannot parse question - name: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &q.type_); err != nil {
		return q, fmt.Errorf("cannot parse question - type: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &q.class); err != nil {
		return q, fmt.Errorf("cannot parse question - class: %w", err)
	}
	return q, nil
}

func decodeName(r *bytes.Reader) ([]byte, error) {
	parts := make([]string, 0)
	length, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("cannot decode name, reading length: %w", err)
	}
	for length != 0 {
		if length&0b1100_0000 == 0b1100_0000 {
			res, err := decodeCompressedName(length, r)
			if err != nil {
				return nil, err
			}
			parts = append(parts, string(res))
			break
		} else {
			buf := make([]byte, length)
			_, err := r.Read(buf)
			if err != nil {
				return nil, fmt.Errorf("cannot decode name, reading name: %w", err)
			}
			parts = append(parts, string(buf))
		}
		length, err = r.ReadByte()
		if length == 0 {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("cannot decode name, reading from buffer: %w", err)
		}
	}

	return []byte(strings.Join(parts, ".")), nil
}

func decodeCompressedName(length byte, r *bytes.Reader) ([]byte, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	pointerBytes := [2]byte{length & 0b0011_1111, b}
	var pointer uint16
	binary.Read(bytes.NewBuffer(pointerBytes[:]), binary.BigEndian, &pointer)

	buf := make([]byte, r.Len()+len(pointerBytes))
	if _, err := r.ReadAt(buf, int64(pointer)); err != nil {
		return nil, err
	}

	r2 := bytes.NewReader(buf)
	return decodeName(r2)
}

func parseDNSRecord(r *bytes.Reader) (DNSRecord, error) {
	rec := DNSRecord{}
	var err error
	rec.name, err = decodeName(r)
	if err != nil {
		return rec, err
	}
	binary.Read(r, binary.BigEndian, &rec.type_)
	binary.Read(r, binary.BigEndian, &rec.class)
	binary.Read(r, binary.BigEndian, &rec.ttl)
	var dataLen uint16
	binary.Read(r, binary.BigEndian, &dataLen)
	rec.data = make([]byte, dataLen)
	_, err = r.Read(rec.data)
	if err != nil {
		return rec, err
	}
	return rec, nil
}

type DNSPacket struct {
	header      DNSHeader
	questions   []DNSQuestion
	answers     []DNSRecord
	authorities []DNSRecord
	additionals []DNSRecord
}

func parseDNSPacket(data []byte) (DNSPacket, error) {
	r := bytes.NewReader(data)
	header, err := parseDNSHeader(r)
	packet := DNSPacket{}
	if err != nil {
		return packet, fmt.Errorf("could not parse DNSHeader: %w", err)
	}
	var i uint16
	packet.questions = make([]DNSQuestion, 0, header.numQuestions)
	for i = 0; i < header.numQuestions; i++ {
		question, err := parseQuestion(r)
		if err != nil {
			return packet, fmt.Errorf("could not parse DNSQuestion: %w", err)
		}
		packet.questions = append(packet.questions, question)
	}

	packet.answers = make([]DNSRecord, 0, header.numAnswers)
	for i = 0; i < header.numAnswers; i++ {
		rec, err := parseDNSRecord(r)
		if err != nil {
			return packet, fmt.Errorf("could not parse answer DNSRecord: %w", err)
		}
		packet.answers = append(packet.answers, rec)
	}

	packet.authorities = make([]DNSRecord, 0, header.numAuthorities)
	for i = 0; i < header.numAuthorities; i++ {
		rec, err := parseDNSRecord(r)
		if err != nil {
			return packet, fmt.Errorf("could not parse authority DNSRecord: %w", err)
		}

		packet.authorities = append(packet.authorities, rec)
	}

	packet.additionals = make([]DNSRecord, 0, header.numAdditionals)
	for i = 0; i < header.numAdditionals; i++ {
		rec, err := parseDNSRecord(r)
		if err != nil {
			return packet, fmt.Errorf("could not parse additional DNSRecord: %w", err)
		}

		packet.additionals = append(packet.additionals, rec)
	}
	return packet, nil
}

func ipToString(data []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
}

func lookupDomain(domainName string) (string, error) {
	query := buildQuery(domainName, TYPE_A)
	// fmt.Printf("query: %x\n", query)
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", fmt.Errorf("cannot connect to DNS: %w", err)
	}
	defer conn.Close()
	_, err = conn.Write(query)
	if err != nil {
		return "", fmt.Errorf("cannot write to connection: %w", err)
	}
	p := make([]byte, 1024)
	n, err := bufio.NewReader(conn).Read(p)
	if err != nil {
		return "", fmt.Errorf("cannot read from connection: %w", err)
	}
	packet, err := parseDNSPacket(p[:n])
	if err != nil {
		return "", fmt.Errorf("cannot parse DNSPacket: %w", err)
	}
	return ipToString(packet.answers[0].data), nil
}

func main() {
	if ip, err := lookupDomain(os.Args[1]); err != nil {
		log.Fatal(err)
	} else {
		log.Printf("IP: %v\n", ip)
	}

}
