package input

// ParsedHost is the common representation of a network host produced by any
// input parser.  Parsers fill only the fields they have data for.
type ParsedHost struct {
	// Source is the file type that produced this record.
	Source FileType

	// Primary IP addresses observed for this host.
	Addresses []string

	// Hostnames / DNS names.
	Names []string

	// OS description (best guess).
	OS string

	// Services observed on the host.
	Services []ParsedService

	// Generic key→value attributes from the source data.
	Attributes map[string]string

	// Unique fingerprints used for cross-source correlation.
	// Keys:   "ssh_hostkey_fp", "tls_cert_fp", "smb_guid", "snmpv3_engine_id"
	UniqueKeys map[string]string
}

// ParsedService represents one observed network service.
type ParsedService struct {
	Address   string
	Port      string
	Protocol  string // "tcp" / "udp"
	Product   string
	Version   string
	// Extra key→value information about the service.
	Attributes map[string]string
}

// ParseResult holds the output of a parser run.
type ParseResult struct {
	Hosts []*ParsedHost
}
