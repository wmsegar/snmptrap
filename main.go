package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	dynatrace "github.com/dtcookie/dynatrace/notification"
	snmp "github.com/soniah/gosnmp"
)

var config *dynatrace.Config

// SNMPHandler A Problem Event Handler for Dynatrace Problem Notifications
type SNMPHandler struct {
	dynatrace.Handler
	Target  string
	Port    uint16
	Version snmp.SnmpVersion
}

// Handle handles a resolved problem
func (handler *SNMPHandler) Handle(event *dynatrace.ProblemEvent) error {
	var err error
	var jsonstr string

	if config.Verbose {
		if jsonstr, err = toJSON(event); err == nil {
			fmt.Println(jsonstr)
			fmt.Println()
		}
	}

	snmp.Default.Target = handler.Target
	snmp.Default.Port = handler.Port
	snmp.Default.Version = handler.Version

	if err = snmp.Default.Connect(); err != nil {
		log.Fatalf("Connect() err: %v", err.Error())
		return nil
	}
	defer snmp.Default.Conn.Close()

	snmpTrapOID := "1.3.6.1.4.1.31094"
	sysDescr := "1.3.6.1.2.1.1.1.0"
	dynaTraceTrapNotification := "1.3.6.1.4.1.31094.0"
	dynaTraceIncidentStart := dynaTraceTrapNotification + ".1"
	dynaTraceIncidentEnd := dynaTraceTrapNotification + ".2"
	dynaTraceIncidentID := dynaTraceTrapNotification + ".3"

	dynaTraceIncident := "1.3.6.1.4.1.31094.1"
	dynaTraceIncidentName := dynaTraceIncident + ".1"
	dynaTraceImpactedEntity := dynaTraceIncident + ".2"
	dynaTraceIncidentTags := dynaTraceIncident + ".3"
	dynaTraceIncidentState := dynaTraceIncident + ".4"
	dynaTraceIncidentSeverity := dynaTraceIncident + ".5"
	dynaTraceIncidentImpact := dynaTraceIncident + ".6"

	pduIncidentStart := snmp.SnmpPDU{
		Name:  dynaTraceIncidentStart,
		Type:  snmp.OctetString,
		Value: fmt.Sprintf("%d", event.Problem.StartTime),
	}
	pduIncidentEnd := snmp.SnmpPDU{
		Name:  dynaTraceIncidentEnd,
		Type:  snmp.OctetString,
		Value: fmt.Sprintf("%d", event.Problem.EndTime),
	}
	pduIncidentID := snmp.SnmpPDU{
		Name:  dynaTraceIncidentID,
		Type:  snmp.OctetString,
		Value: event.Notification.PID,
	}
	pduDescription := snmp.SnmpPDU{
		Name:  sysDescr,
		Type:  snmp.OctetString,
		Value: "dynaTrace Trap",
	}
	pduIncidentName := snmp.SnmpPDU{
		Name:  dynaTraceIncidentName,
		Type:  snmp.OctetString,
		Value: event.Notification.Title,
	}
	pduImpactedEntity := snmp.SnmpPDU{
		Name:  dynaTraceImpactedEntity,
		Type:  snmp.OctetString,
		Value: event.Notification.ImpactedEntity,
	}
	pduIncidentTags := snmp.SnmpPDU{
		Name:  dynaTraceIncidentTags,
		Type:  snmp.OctetString,
		Value: event.Notification.Tags,
	}
	pduIncidentState := snmp.SnmpPDU{
		Name:  dynaTraceIncidentState,
		Type:  snmp.OctetString,
		Value: event.Notification.State,
	}
	pduIncidentSeverity := snmp.SnmpPDU{
		Name:  dynaTraceIncidentSeverity,
		Type:  snmp.OctetString,
		Value: event.Notification.Severity,
	}
	pduIncidentImpact := snmp.SnmpPDU{
		Name:  dynaTraceIncidentImpact,
		Type:  snmp.OctetString,
		Value: event.Notification.Impact,
	}

	trap := snmp.SnmpTrap{
		Variables: []snmp.SnmpPDU{
			pduIncidentStart,
			pduIncidentEnd,
			pduIncidentID,
			pduDescription,
			pduIncidentName,
			pduImpactedEntity,
			pduIncidentTags,
			pduIncidentState,
			pduIncidentSeverity,
			pduIncidentImpact},
		Enterprise:   snmpTrapOID,
		AgentAddress: "127.0.0.1",
		GenericTrap:  0,
		SpecificTrap: 0,
		Timestamp:    300,
	}

	if _, err = snmp.Default.SendTrap(trap); err != nil {
		log.Fatalf("SendTrap() err: %v", err.Error())
		return nil
	}

	return nil
}

func toJSON(v interface{}) (string, error) {
	var err error
	var bytes []byte
	if bytes, err = json.MarshalIndent(v, "", "  "); err != nil {
		return "", err
	}
	return string(bytes), nil
}

func main() {
	var err error
	var config *dynatrace.Config
	var handler SNMPHandler
	if config = parseConfig(&handler); config == nil {
		return
	}

	if idx := strings.Index(handler.Target, ":"); idx != -1 {
		target := handler.Target
		handler.Target = target[:idx]
		var port int
		if port, err = strconv.Atoi(target[idx+1:]); err != nil {
			fmt.Println(err.Error())
			return
		}
		handler.Port = uint16(port)
	} else {
		handler.Port = 162
	}

	handler.Version = snmp.Version1

	dynatrace.Listen(config, &handler)
}

func parseConfig(handler *SNMPHandler) *dynatrace.Config {
	var err error

	flagSet := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flagSet.StringVar(&handler.Target, "target", "", "")
	if config, err = dynatrace.ParseConfig(flagSet); err != nil {
		if !strings.HasPrefix(err.Error(), "flag provided but not defined") {
			fmt.Println(err.Error())
			usage()
		}
		return nil
	}

	if handler.Target == "" {
		fmt.Println("no target specified")
		usage()
		return nil
	}

	return config
}

func usage() {
	fmt.Println()
	fmt.Println("USAGE: snmphub [-api-base-url <api-base-url>] [-api-token <api-token>] [-listen <listen-port>] [-target <host[:port]>")
	fmt.Println("  Hint: you can also define the environment variables DT_API_BASE_URL, DT_API_TOKEN and DT_LISTEN_PORT")
	fmt.Println("  Hint: you can also specify the -config flag referring to a JSON file containing the parameters")
}
