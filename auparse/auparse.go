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

package auparse

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

//go:generate sh -c "go run mk_audit_msg_types.go && gofmt -s -w zaudit_msg_types.go"
//go:generate sh -c "perl mk_audit_syscalls.pl > zaudit_syscalls.go && gofmt -s -w zaudit_syscalls.go"
//go:generate perl mk_audit_arches.pl
//go:generate go run mk_audit_exit_codes.go

const (
	typeToken = "type="
	msgToken  = "msg="
)

var (
	// errInvalidAuditHeader means some part of the audit header was invalid.
	errInvalidAuditHeader = errors.New("invalid audit message header")
	// errParseFailure indicates a generic failure to parse.
	errParseFailure             = errors.New("failed to parse audit message")
	errMessageWithoutData       = errors.New("message has no data content")
	errArchKeyNotFound          = errors.New("arch key not found")
	errSyscallKeyNotFound       = errors.New("syscall key not found")
	errArchKeyNotFoundInSyscall = errors.New("arch key not found so syscall cannot be translated to a name")
	errSigKeyNotFound           = errors.New("sig key not found")
	errSaddrKeyNotFound         = errors.New("saddr key not found")
	errArgcKeyNotFound          = errors.New("argc key not found")
	errSuccessResKeysNotFound   = errors.New("success and res key not found")
	errExitKeyNotFound          = errors.New("exit key not found")
	errSELinuxKeyNotFound       = errors.New("SELinux: subj or obj key not found")
	errSELinuxContextFieldSplit = errors.New("failed to split SELinux context field")
	errHexEncodeKeyNotFound     = errors.New("hexEncode: key not found")
)

// AuditMessage represents a single audit message.
type AuditMessage struct {
	RecordType AuditMessageType // Record type from netlink header.
	Timestamp  time.Time        // Timestamp parsed from payload in netlink message.
	Sequence   uint32           // Sequence parsed from payload.
	RawData    string           // Raw message as a string.

	fields map[string]field
	offset int               // offset is the index into RawData where the header ends and message begins.
	data   map[string]string // The key value pairs parsed from the message.
	tags   []string          // The keys associated with the event (e.g. the values set in rules with -F key=exec).
	error  error             // Error that occurred while parsing.
}

type field struct {
	orig  string // Original field value parse from message (including quotes).
	value string // Parsed and enriched value.
}

func newField(orig string) field  { return field{orig: orig, value: orig} }
func (f *field) Orig() string     { return f.orig }
func (f *field) Value() string    { return f.value }
func (f *field) Set(value string) { f.value = value }

// Data returns the key-value pairs that are contained in the audit message.
// This information is parsed from the raw message text the first time this
// method is called, all future invocations return the stored result. A nil
// map may be returned error is non-nil. A non-nil error is returned if there
// was a failure parsing or enriching the data.
func (m *AuditMessage) Data() (map[string]string, error) {
	return m.DataB(map[string]field{}, map[string]string{})
}

func (m *AuditMessage) DataB(fields map[string]field, data map[string]string) (map[string]string, error) {
	if m.data != nil || m.error != nil {
		return m.data, m.error
	}

	for k := range fields {
		delete(fields, k)
	}

	if m.offset < 0 {
		m.error = errMessageWithoutData
		return nil, m.error
	}

	message, err := normalizeAuditMessage(m.RecordType, m.RawData[m.offset:])
	if err != nil {
		m.error = err
		return nil, m.error
	}

	m.fields = fields
	defer func() { m.fields = nil }()
	extractKeyValuePairs(message, m.fields)

	if err = enrichData(m); err != nil {
		m.error = err
		return nil, m.error
	}

	for k := range data {
		delete(data, k)
	}
	m.data = data
	for k, f := range m.fields {
		m.data[k] = f.Value()
	}

	return m.data, m.error
}

func (m *AuditMessage) Tags() ([]string, error) {
	_, err := m.Data()
	return m.tags, err
}

// ToMapStr returns a new map containing the parsed key value pairs, the
// record_type, @timestamp, and sequence. The parsed key value pairs have
// a lower precedence than the well-known keys and will not override them.
// If an error occurred while parsing the message then an error key will be
// present.
func (m *AuditMessage) ToMapStr() map[string]interface{} {
	// Ensure event has been parsed.
	data, err := m.Data()

	out := make(map[string]interface{}, len(data)+5)
	for k, v := range data {
		out[k] = v
	}

	out["record_type"] = m.RecordType.String()
	out["@timestamp"] = m.Timestamp.UTC().String()
	out["sequence"] = strconv.FormatUint(uint64(m.Sequence), 10)
	out["raw_msg"] = m.RawData
	if len(m.tags) > 0 {
		out["tags"] = m.tags
	}
	if err != nil {
		out["error"] = err.Error()
	}
	return out
}

// ParseLogLine parses an audit message as logged by the Linux audit daemon.
// It expects logs line that begin with the message type. For example,
// "type=SYSCALL msg=audit(1488862769.030:19469538)". A non-nil error is
// returned if it fails to parse the message header (type, timestamp, sequence).
func ParseLogLine(line string) (AuditMessage, error) {
	msgIndex := strings.Index(line, msgToken)
	if msgIndex == -1 {
		return AuditMessage{}, errInvalidAuditHeader
	}

	// Verify type=XXX is before msg=
	if msgIndex < len(typeToken)+1 {
		return AuditMessage{}, errInvalidAuditHeader
	}

	// Convert the type to a number (i.e. type=SYSCALL -> 1300).
	typName := line[len(typeToken) : msgIndex-1]
	typ, err := GetAuditMessageType(typName)
	if err != nil {
		return AuditMessage{}, err
	}

	msg := line[msgIndex+len(msgToken):]
	return Parse(typ, msg)
}

// Parse parses an audit message in the format it was received from the kernel.
// It expects a message type, which is the message type value from the netlink
// header, and a message, which is raw data from the netlink message. The
// message should begin the the audit header that contains the timestamp and
// sequence number -- "audit(1488862769.030:19469538)".
//
// A non-nil error is returned if it fails to parse the message header
// (timestamp, sequence).
func Parse(typ AuditMessageType, message string) (AuditMessage, error) {
	message = strings.TrimSpace(message)

	timestamp, seq, end, err := parseAuditHeader(message)
	if err != nil {
		return AuditMessage{}, err
	}

	return AuditMessage{
		RecordType: typ,
		Timestamp:  timestamp,
		Sequence:   seq,
		offset:     indexOfMessage(message[end:]),
		RawData:    message,
	}, nil
}

// parseAuditHeader parses the timestamp and sequence number from the audit
// message header that has the form of "audit(1490137971.011:50406):".
func parseAuditHeader(line string) (time.Time, uint32, int, error) {
	// Find tokens.
	start := strings.IndexRune(line, '(')
	if start == -1 {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	dot := strings.IndexRune(line[start:], '.')
	if dot == -1 {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	dot += start
	sep := strings.IndexRune(line[dot:], ':')
	if sep == -1 {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	sep += dot
	end := strings.IndexRune(line[sep:], ')')
	if end == -1 {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	end += sep

	// Parse timestamp.
	sec, err := strconv.ParseInt(line[start+1:dot], 10, 64)
	if err != nil {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	msec, err := strconv.ParseInt(line[dot+1:sep], 10, 64)
	if err != nil {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}
	tm := time.Unix(sec, msec*int64(time.Millisecond)).UTC()

	// Parse sequence.
	sequence, err := strconv.ParseUint(line[sep+1:end], 10, 32)
	if err != nil {
		return time.Time{}, 0, 0, errInvalidAuditHeader
	}

	return tm, uint32(sequence), end, nil
}

func indexOfMessage(msg string) int {
	return strings.IndexFunc(msg, func(r rune) bool {
		switch r {
		case ':', ' ':
			return true
		default:
			return false
		}
	})
}

// Key/Value Parsing Helpers

var (
	// avcMessageRegex matches the beginning of SELinux AVC messages to parse
	// the seresult and seperms parameters.
	// Example: "avc:  denied  { read } for  "
	selinuxAVCMessageRegex = regexp.MustCompile(`avc:\s+(\w+)\s+\{\s*(.*)\s*\}\s+for\s+`)
)

// normalizeAuditMessage fixes some of the peculiarities of certain audit
// messages in order to make them parsable as key-value pairs.
func normalizeAuditMessage(typ AuditMessageType, msg string) (string, error) {
	switch typ {
	case AUDIT_AVC:
		i := selinuxAVCMessageRegex.FindStringSubmatchIndex(msg)
		if i == nil {
			// It's a different type of AVC (e.g. AppArmor) and doesn't require
			// normalization to make it parsable.
			return msg, nil
		}

		// This selinux AVC regex match should return three pairs.
		if len(i) != 3*2 {
			return "", errParseFailure
		}
		perms := strings.Fields(msg[i[4]:i[5]])
		msg = fmt.Sprintf("seresult=%v seperms=%v %v", msg[i[2]:i[3]], strings.Join(perms, ","), msg[i[1]:])
	case AUDIT_LOGIN:
		msg = strings.Replace(msg, "old ", "old_", 2)
		msg = strings.Replace(msg, "new ", "new_", 2)
	}

	return msg, nil
}

func isKeyRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-'
}

func isInterestingValue(v string) bool {
	switch v {
	case "", "?", "?,", "(null)":
		return false
	default:
		return true
	}
}

func saveKeyValue(key, origValue, value string, data map[string]field) {
	if key == "msg" {
		extractKeyValuePairs(value, data)
	} else if isInterestingValue(value) {
		data[key] = field{origValue, value}
	}
}

func extractKeyValuePairs(msg string, data map[string]field) {
	type parseState int
	const (
		skipState parseState = iota
		keyState
		valueBeginState
		plainValueState
		quotedValueState
	)
	state := skipState
	var keyStart, valueStart int
	var key string
	var quote rune
	var backslash bool
	for i, r := range msg {
		switch state {
		case skipState:
			if isKeyRune(r) {
				state = keyState
				keyStart = i
			}
		case keyState:
			if isKeyRune(r) {
				continue
			}
			if r != '=' {
				state = skipState
				continue
			}
			key = msg[keyStart:i]
			state = valueBeginState
		case valueBeginState:
			valueStart = i
			if r == '\'' || r == '"' {
				quote = r
				state = quotedValueState
				backslash = false
				continue
			}
			state = plainValueState
			fallthrough
		case plainValueState:
			if r != '\'' && r != '"' && !unicode.IsSpace(r) {
				continue
			}
			v := msg[valueStart:i]
			saveKeyValue(key, v, v, data)
			state = skipState
		case quotedValueState:
			if r == quote && !backslash {
				v := msg[valueStart+1 : i]
				saveKeyValue(key, msg[valueStart:i+1], v, data)
				state = skipState
			}
			backslash = r == '\\'
		}
	}
	// at the end of the loop the only "valid" state that needs processing
	// is plainValueState. everything else can be ignored.
	if state == plainValueState {
		v := msg[valueStart:]
		saveKeyValue(key, v, v, data)
	}
}

// Enrichment after KV parsing

func enrichData(msg *AuditMessage) error {
	normalizeUnsetID("auid", msg.fields)
	normalizeUnsetID("old-auid", msg.fields)
	normalizeUnsetID("ses", msg.fields)

	// Many different message types can have subj field so check them all.
	parseSELinuxContext("subj", msg.fields)

	// Normalize success/res to result.
	result(msg.fields)

	// Convert exit codes to named POSIX exit codes.
	exit(msg.fields)

	// Normalize keys that are of the form key="key=user_command".
	auditRuleKey(msg)

	hexDecode("cwd", msg.fields)

	switch msg.RecordType {
	case AUDIT_SECCOMP:
		if err := setSignalName(msg.fields); err != nil {
			return err
		}
		fallthrough
	case AUDIT_SYSCALL:
		if err := arch(msg.fields); err != nil {
			return err
		}
		if err := setSyscallName(msg.fields); err != nil {
			return err
		}
		if err := hexDecode("exe", msg.fields); err != nil {
			return errors.WithMessage(err, "exe")
		}
	case AUDIT_SOCKADDR:
		if err := saddr(msg.fields); err != nil {
			return err
		}
	case AUDIT_PROCTITLE:
		if err := hexDecode("proctitle", msg.fields); err != nil {
			return errors.WithMessage(err, "proctitle")
		}
	case AUDIT_USER_CMD:
		if err := hexDecode("cmd", msg.fields); err != nil {
			return errors.WithMessage(err, "cmd")
		}
	case AUDIT_TTY, AUDIT_USER_TTY:
		if err := hexDecode("data", msg.fields); err != nil {
			return errors.WithMessage(err, "data")
		}
	case AUDIT_EXECVE:
		if err := execveArgs(msg.fields); err != nil {
			return err
		}
	case AUDIT_PATH:
		parseSELinuxContext("obj", msg.fields)
		hexDecode("name", msg.fields)
	case AUDIT_USER_LOGIN:
		// acct only exists in failed logins.
		hexDecode("acct", msg.fields)
	}

	return nil
}

func arch(data map[string]field) error {
	field, found := data["arch"]
	if !found {
		return errArchKeyNotFound
	}

	arch, err := strconv.ParseInt(field.Value(), 16, 64)
	if err != nil {
		return errors.Wrap(err, "failed to parse arch")
	}

	field.Set(AuditArch(arch).String())
	data["arch"] = field
	return nil
}

func setSyscallName(data map[string]field) error {
	field, found := data["syscall"]
	if !found {
		return errSyscallKeyNotFound
	}

	syscall, err := strconv.Atoi(field.Value())
	if err != nil {
		return errors.Wrap(err, "failed to parse syscall")
	}

	arch, found := data["arch"]
	if !found {
		return errArchKeyNotFoundInSyscall
	}

	if name, found := AuditSyscalls[arch.Value()][syscall]; found {
		field.Set(name)
		data["syscall"] = field
	}
	return nil
}

func setSignalName(data map[string]field) error {
	field, found := data["sig"]
	if !found {
		return errSigKeyNotFound
	}

	signalNum, err := strconv.Atoi(field.Value())
	if err != nil {
		return errors.Wrap(err, "failed to parse sig")
	}

	if signalName := unix.SignalName(syscall.Signal(signalNum)); signalName != "" {
		field.Set(signalName)
		data["sig"] = field
	}
	return nil
}

func saddr(data map[string]field) error {
	field, found := data["saddr"]
	if !found {
		return errSaddrKeyNotFound
	}

	saddrData, err := parseSockaddr(field.Value())
	if err != nil {
		return errors.Wrap(err, "failed to parse saddr")
	}

	delete(data, "saddr")
	for k, v := range saddrData {
		data[k] = newField(v)
	}
	return nil
}

func normalizeUnsetID(key string, data map[string]field) {
	field, found := data[key]
	if !found {
		return
	}

	switch field.Value() {
	case "4294967295", "-1":
		field.Set("unset")
		data[key] = field
	}
}

func hexDecode(key string, data map[string]field) error {
	field, found := data[key]
	if !found {
		return errHexEncodeKeyNotFound
	}
	if len(field.Orig()) == 0 || len(field.Orig())%2 == 1 {
		return nil
	}

	src := field.Orig()
	var dst strings.Builder
	dst.Grow(hex.DecodedLen(len(src)))
	for i := 0; i < len(src)/2; i++ {
		a, ok := fromHexChar(src[i*2])
		if !ok {
			return nil
		}
		b, ok := fromHexChar(src[i*2+1])
		if !ok {
			return nil
		}
		c := (a << 4) | b
		if c == 0 {
			c = ' '
		}
		dst.WriteByte(c)
	}

	field.Set(dst.String())
	data[key] = field
	return nil
}

func execveArgs(data map[string]field) error {
	argc, found := data["argc"]
	if !found {
		return errArgcKeyNotFound
	}

	count, err := strconv.ParseUint(argc.Value(), 10, 32)
	if err != nil {
		return errors.Wrapf(err, "failed to convert argc='%v' to number", argc)
	}

	for i := 0; i < int(count); i++ {
		key := "a" + strconv.Itoa(i)

		arg, found := data[key]
		if !found {
			return errors.Errorf("failed to find arg %v", key)
		}

		if ascii, err := hexToString(arg.Orig()); err == nil {
			arg.Set(ascii)
			data[key] = arg
		}
	}

	return nil
}

// parseSELinuxContext parses a SELinux security context of the form
// 'user:role:domain:level:category'.
func parseSELinuxContext(key string, data map[string]field) error {
	field, found := data[key]
	if !found {
		return errSELinuxKeyNotFound
	}

	keys := []string{"_user", "_role", "_domain", "_level", "_category"}
	contextParts := strings.SplitN(field.Value(), ":", len(keys))
	if len(contextParts) == 0 {
		return errSELinuxContextFieldSplit
	}
	delete(data, key)

	for i, part := range contextParts {
		data[key+keys[i]] = newField(part)
	}
	return nil
}

func result(data map[string]field) error {
	// Syscall messages use "success". Other messages use "res".
	field, found := data["success"]
	if !found {
		field, found = data["res"]
		if !found {
			return errSuccessResKeysNotFound
		}
		delete(data, "res")
	} else {
		delete(data, "success")
	}

	switch v := strings.ToLower(field.Value()); {
	case v == "yes", v == "1", strings.HasPrefix(v, "suc"):
		data["result"] = newField("success")
	default:
		data["result"] = newField("fail")
	}
	return nil
}

func auditRuleKey(msg *AuditMessage) {
	field, found := msg.fields["key"]
	if !found {
		return
	}
	delete(msg.fields, "key")

	// Handle hex encoded data (e.g. key=28696E7).
	if decodedData, err := decodeUppercaseHexString(field.Orig()); err == nil {
		keys := strings.Split(string(decodedData), string([]byte{0x01}))
		msg.tags = keys
		return
	}

	parts := strings.SplitN(field.Value(), "=", 2)
	if len(parts) == 1 {
		// Handle key="net".
		msg.tags = parts
	} else if len(parts) == 2 {
		// Handle key="key=net".
		msg.tags = parts[1:]
	}
}

func exit(data map[string]field) error {
	field, found := data["exit"]
	if !found {
		return errExitKeyNotFound
	}

	exitCode, err := strconv.Atoi(field.Value())
	if err != nil {
		return errors.Wrap(err, "failed to parse exit")
	}

	if exitCode >= 0 {
		return nil
	}

	name, found := AuditErrnoToName[-1*exitCode]
	if !found {
		return nil
	}

	field.Set(name)
	data["exit"] = field
	return nil
}
