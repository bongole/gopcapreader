// Copyright 2012 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file contains the glue between the pcap library and this one.

package gopcapreader

import (
	"errors"
	"fmt"
	pcap "github.com/akrennmair/gopcap"
	"net"
	"time"
)

// A single TCP packet
type TcpPacket struct {
	pkt *pcap.Packet
	tcp *pcap.Tcphdr
}

// Decodes a pcap.Packet and wraps it in a TcpPacket object.
func NewTcpPacket(p *pcap.Packet) (pkt *TcpPacket, err error) {
	defer func() {
		if r := recover(); r != nil {
			pkt = nil
			err = errors.New("Decode failed")
			return
		}
	}()
	p.Decode()
	tcp, ok := p.Headers[len(p.Headers)-1].(*pcap.Tcphdr)
	if !ok {
		return nil, errors.New("Doesn't appear to be a TCP packet")
	}
	return &TcpPacket{pkt: p, tcp: tcp}, nil
}

// Returns TcpPacket as an orderedData object.
func (p *TcpPacket) asData() *orderedData {
	d := &orderedData{
		Payload: p.pkt.Payload,
		IsFirst: p.tcp.Flags&pcap.TCP_SYN != 0,
		IsLast:  p.tcp.Flags&(pcap.TCP_FIN|pcap.TCP_RST) != 0,
		Start:   uint64(p.tcp.Seq),
	}
	d.Limit = d.Start + uint64(len(d.Payload))
	if p.tcp.Flags&pcap.TCP_SYN != 0 {
		d.Limit++
	}
	if p.tcp.Flags&pcap.TCP_FIN != 0 {
		d.Limit++
	}
	return d
}

// A key for mapping a packet to a TCP stream, used by the Multiplexer.
type TcpKey struct {
	IpVersion         byte
	SrcIp, DestIp     [16]byte
	SrcPort, DestPort uint16
}

// Returns a new TcpKey that's the reverse of the current key
// (src/dst are switched)
func (p TcpKey) Reverse() TcpKey {
	return TcpKey{
		IpVersion: p.IpVersion,
		SrcIp:     p.DestIp,
		DestIp:    p.SrcIp,
		SrcPort:   p.DestPort,
		DestPort:  p.SrcPort,
	}
}

// Returns the source and destination IPs of the key as net.IP objects.
func (p TcpKey) NetIPs() (src, dst net.IP) {
	if p.IpVersion == 4 {
		src, dst = p.SrcIp[:4], p.DestIp[:4]
	} else {
		src, dst = p.SrcIp[:], p.DestIp[:]
	}
	return
}

// Prints the TcpKey as a human-readable string.
func (p TcpKey) String() string {
	src, dst := p.NetIPs()
	return fmt.Sprintf("%v[%v]->%v[%v]", src, p.SrcPort, dst, p.DestPort)
}

// Half of a TcpKey.  Used for specifying just the source or destination
// IP/port pair of a stream.
type TcpHalfKey struct {
	IpVersion byte
	Ip        [16]byte
	Port      uint16
}

// Returns the IP of the TcpHalfKey as a net.IP object
func (p TcpHalfKey) NetIP() net.IP {
	if p.IpVersion == 4 {
		return p.Ip[:4]
	}
	return p.Ip[:]
}

// Prints out the TcpHalfKey as a human-readable string.
func (p TcpHalfKey) String() string {
	return fmt.Sprintf("%v[%v]", p.NetIP(), p.Port)
}

// Returns the two half-keys of a given TcpKey
func (p TcpKey) HalfKeys() (src, dst TcpHalfKey) {
	src.IpVersion, dst.IpVersion = p.IpVersion, p.IpVersion
	src.Ip, src.Port = p.SrcIp, p.SrcPort
	dst.Ip, dst.Port = p.DestIp, p.DestPort
	return
}

// Returns the TcpKey of a packet, or an error if unable to create it.
func (p *TcpPacket) TcpKey() (TcpKey, error) {
	key := TcpKey{}
	if ip4hdr, ok4 := p.pkt.Headers[0].(*pcap.Iphdr); ok4 {
		copy(key.SrcIp[:4], ip4hdr.SrcIp)
		copy(key.DestIp[:4], ip4hdr.DestIp)
		key.IpVersion = 4
	} else if ip6hdr, ok6 := p.pkt.Headers[0].(*pcap.Ip6hdr); ok6 {
		copy(key.SrcIp[:16], ip6hdr.SrcIp)
		copy(key.DestIp[:16], ip6hdr.DestIp)
		key.IpVersion = 6
	} else {
		return key, errors.New("Not an IP4 or IP6 packet")
	}
	key.SrcPort = p.tcp.SrcPort
	key.DestPort = p.tcp.DestPort
	return key, nil
}

// Read data in from the given pcap.Pcap handle, multiplexing all packets into
// streams and processing those streams with its stream handler.  If 'packets'
// is given and > 0, will return after that many packets have been processed.
// Otherwise runs forever.
func (m *Multiplexer) MultiplexPcap(pcap_handle *pcap.Pcap, packets int) {
	count := 0
	start := time.Now()
	defer func() {
		gplog(logError, "Dropped", m.PacketsDroppedPrimaryBufferFull,
			"packets out of", count)
		runTime := float64(time.Now().Sub(start)) / float64(time.Second)
		gplog(logError, "Processed",
			float64(count-m.PacketsDroppedPrimaryBufferFull)/runTime,
			"packets per second")
	}()
	for pkt := pcap_handle.Next(); ; pkt = pcap_handle.Next() {
		count++
		if packets > 0 && count >= packets {
			gplog(logError, "Count exceeds requested packets, returning from multiplexer")
			return
		}
		if count%1000000 == 0 {
			gplog(logInfo, "Processed", count, "packets so far")
		}
		if pkt == nil {
			gplog(logWarning, "Pcap returned us a nil packet")
			continue
		}
		select {
		case m.packets <- pkt:
		default:
			m.PacketsDroppedPrimaryBufferFull++
		}
	}
}
