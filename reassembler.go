// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package libaudit

import (
	"container/heap"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/elastic/go-libaudit/v2/auparse"
)

var errReassemblerClosed = errors.New("reassembler closed")

// Stream is implemented by the user of the Reassembler to handle reassembled
// audit data.
type Stream interface {
	// ReassemblyComplete notifies that a complete group of events has been
	// received and provides those events.
	ReassemblyComplete(msgs []auparse.AuditMessage)

	// EventsLost notifies that some events were lost. This is based on gaps
	// in the sequence numbers of received messages. Lost events can be caused
	// by a slow receiver or because the kernel is configured to rate limit
	// events.
	EventsLost(count int)
}

// Type - Reassembler

// Reassembler combines related messages in to an event based on their timestamp
// and sequence number. It handles messages that may be have been received out
// of order or are interleaved. Reassembler is concurrency-safe.
//
// The Reassembler uses callbacks (see Stream interface) to notify the user of
// completed messages. Callbacks for reassembled events will occur in order of
// sequence number unless a late message is received that falls outside of the
// sequences held in memory.
type Reassembler struct {
	closed int32 // closed is set to 1 when after the Reassembler is closed.

	// cache contains the in-flight event messages. Eviction occurs when an
	// event is completed via an EOE message, the cache reaches max size
	// (lowest sequence is evicted first), or an event expires base on time.
	list *eventList

	// stream is the callback interface used for delivering completed events.
	stream Stream
}

// NewReassembler returns a new Reassembler. maxInFlight controls the maximum
// number of events (based on timestamp + sequence) that are buffered. timeout
// controls how long the Reassembler waits for an EOE message (end-of-event)
// before evicting the event. And stream receives the callbacks for completed
// events and lost events.
func NewReassembler(maxInFlight int, timeout time.Duration, stream Stream) (*Reassembler, error) {
	if stream == nil {
		return nil, errors.New("stream cannot be nil")
	}

	return &Reassembler{
		list:   newEventList(maxInFlight, timeout),
		stream: stream,
	}, nil
}

// PushMessage pushes a new AuditMessage message into the Reassembler. Callbacks
// may be triggered as a result.
func (r *Reassembler) PushMessage(msg auparse.AuditMessage) {
	r.list.Put(msg)
	evicted, lost := r.list.CleanUp()
	r.callback(evicted, lost)
}

// Push pushes a new audit message into the Reassembler. This is a convenence
// function that handles calling auparse.Parse() to extract the message's
// timestamp and sequence number. If parsing fails then an error will be
// returned. See PushMessage.
func (r *Reassembler) Push(msgType auparse.AuditMessageType, rawData []byte) error {
	msg, err := auparse.Parse(msgType, string(rawData))
	if err != nil {
		return err
	}

	r.PushMessage(msg)
	return nil
}

// Maintain performs maintenance on the cached message. It can be called
// periodically to evict timed-out events. It returns a non-nil error if
// the Reassembler has been closed.
func (r *Reassembler) Maintain() error {
	if atomic.LoadInt32(&r.closed) == 1 {
		return errReassemblerClosed
	}
	evicted, lost := r.list.CleanUp()
	r.callback(evicted, lost)
	return nil
}

// Close flushes any cached events and closes the Reassembler.
func (r *Reassembler) Close() error {
	if atomic.CompareAndSwapInt32(&r.closed, 0, 1) {
		evicted, lost := r.list.Clear()
		r.callback(evicted, lost)
		return nil
	}
	return errReassemblerClosed
}

func (r *Reassembler) callback(events []*event, lost int) {
	for _, e := range events {
		r.stream.ReassemblyComplete(e.msgs)
	}

	if lost > 0 {
		r.stream.EventsLost(lost)
	}
}

const maxSortRange = 1<<24 - 1

type intHeap []int

func (h intHeap) Len() int { return len(h) }
func (h intHeap) Less(i, j int) bool {
	if math.Abs(float64(h[i]-h[j])) > maxSortRange {
		return h[i] > h[j]
	}
	return h[i] < h[j]
}
func (h intHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *intHeap) Push(x interface{}) { *h = append(*h, x.(int)) }

func (h *intHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// Type - event

type event struct {
	expireTime time.Time
	msgs       []auparse.AuditMessage
	complete   bool
}

func (e *event) Add(msg auparse.AuditMessage) {
	e.msgs = append(e.msgs, msg)

	// These messages all signal the completion of an event.
	if msg.RecordType == auparse.AUDIT_PROCTITLE ||
		msg.RecordType <= auparse.AUDIT_LAST_DAEMON ||
		msg.RecordType >= auparse.AUDIT_ANOM_LOGIN_FAILURES {
		e.complete = true
	}
}

func (e *event) IsExpired() bool {
	return time.Now().After(e.expireTime)
}

// Type - eventList

type eventList struct {
	sync.Mutex
	seqs    *intHeap
	events  map[int]*event
	lastSeq int
	maxSize int
	timeout time.Duration
}

func newEventList(maxSize int, timeout time.Duration) *eventList {
	h := &intHeap{}
	heap.Init(h)
	return &eventList{
		seqs:    h,
		events:  make(map[int]*event, maxSize+1),
		maxSize: maxSize,
		timeout: timeout,
	}
}

// remove the first event (lowest sequence) in the list.
func (l *eventList) remove() {
	if l.seqs.Len() > 0 {
		seq := heap.Pop(l.seqs).(int)
		delete(l.events, seq)
	}
}

// Clear removes all events from the list and returns the events and the number
// of list events.
func (l *eventList) Clear() ([]*event, int) {
	l.Lock()
	defer l.Unlock()

	var lost int
	var evicted []*event
	for {
		if l.seqs.Len() == 0 {
			break
		}

		// Get event.
		seq := (*l.seqs)[0]
		event := l.events[seq]

		if l.lastSeq > 0 {
			lost += seq - l.lastSeq - 1
		}
		l.lastSeq = seq
		evicted = append(evicted, event)
		l.remove()
	}

	return evicted, lost
}

// Put a new message in the list.
func (l *eventList) Put(msg auparse.AuditMessage) {
	l.Lock()
	defer l.Unlock()

	seq := int(msg.Sequence)
	e, found := l.events[seq]

	// Mark as complete, but do not append.
	if msg.RecordType == auparse.AUDIT_EOE {
		if found {
			e.complete = true
		}
		return
	}

	if !found {
		heap.Push(l.seqs, seq)

		e = &event{
			expireTime: time.Now().Add(l.timeout),
			msgs:       make([]auparse.AuditMessage, 0, 4),
		}
		l.events[seq] = e
	}

	e.Add(msg)
}

func (l *eventList) CleanUp() ([]*event, int) {
	l.Lock()
	defer l.Unlock()

	var lost int
	var evicted []*event
	for {
		size := l.seqs.Len()
		if size == 0 {
			break
		}

		// Get event.
		seq := (*l.seqs)[0]
		event := l.events[seq]

		if event.complete || size > l.maxSize || event.IsExpired() {
			if l.lastSeq > 0 {
				lost += seq - l.lastSeq - 1
			}
			l.lastSeq = seq
			evicted = append(evicted, event)
			l.remove()
			continue
		}

		break
	}

	return evicted, lost
}
