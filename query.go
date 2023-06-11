package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"math/rand"
	"strings"
)

type DNSHeader struct {
	id             uint16
	flags          uint16
	numQuestions   uint16
	numAnswers     uint16
	numAuthorities uint16
	numAdditionals uint16
}

func (h DNSHeader) toBytes() []byte {
	b := bytes.Buffer{}
	r := bufio.NewWriter(&b)
	binary.Write(r, binary.BigEndian, h.id)
	binary.Write(r, binary.BigEndian, h.flags)
	binary.Write(r, binary.BigEndian, h.numQuestions)
	binary.Write(r, binary.BigEndian, h.numAnswers)
	binary.Write(r, binary.BigEndian, h.numAuthorities)
	binary.Write(r, binary.BigEndian, h.numAdditionals)
	r.Flush()
	return b.Bytes()
}

type DNSQuestion struct {
	name  []byte
	type_ uint16
	class uint16
}

func (q DNSQuestion) toBytes() []byte {
	b := bytes.Buffer{}
	r := bufio.NewWriter(&b)
	r.Write(q.name)
	binary.Write(r, binary.BigEndian, q.type_)
	binary.Write(r, binary.BigEndian, q.class)
	r.Flush()
	return b.Bytes()
}

func encodeDNSName(s string) []byte {
	b := bytes.Buffer{}
	for _, p := range strings.Split(s, ".") {
		b.WriteByte(byte(len(p)))
		b.WriteString(p)
	}
	b.WriteByte(0)
	return b.Bytes()
}

const TYPE_A = 1
const TYPE_NS = 2
const CLASS_IN = 1

func buildQuery(domainName string, recordType uint16) []byte {
	name := encodeDNSName(domainName)
	var id uint16 = uint16(rand.Intn(65535))
	// const RECURSION_DESIRED uint16 = 1 << 8
	header := DNSHeader{id: id, numQuestions: 1, flags: 0}
	question := DNSQuestion{name: name, type_: recordType, class: CLASS_IN}
	b := bytes.Buffer{}
	r := bufio.NewWriter(&b)
	r.Write(header.toBytes())
	r.Write(question.toBytes())
	r.Flush()
	return b.Bytes()
}
