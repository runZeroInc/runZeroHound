package runzero

// runZero Source IDs & Names

const (
	SourceRunZero               = iota + 1
	SourceMiradore              // 2
	SourceAWS                   // 3
	SourceCrowdStrike           // 4
	SourceAzure                 // 5
	SourceCensys                // 6
	SourceVMware                // 7
	SourceGCP                   // 8
	SourceSentinelOne           // 9
	SourceTenable               // 10
	SourceNessus                // 11
	SourceNexpose               // 12
	SourceInsightVM             // 13
	SourceQualys                // 14
	SourceShodan                // 15
	SourceAzureAD               // 16
	SourceLDAP                  // 17
	SourceDefender365           // 18
	SourceIntune                // 19
	SourceGoogleWorkspace       // 20
	SourceSample                // 21
	SourceTenableSecurityCenter // 22
	SourcePacket                // 23
	SourceWiz                   // 24
	SourceMeraki                // 25
	SourceMECM                  // 26
	SourceTanium                // 27
	SourceSimulator             // 28
	SourceNetBox                // 29
	SourceCIP                   // 30
	SourcePaloAltoNetworks      // 31
	SourcePaloAltoPrismaCloud   // 32
	SourceAWSRole               // 33
	SourceDragos                // 34

	SourceCustom = -1
)

// SourceNames map IDs to names
var SourceNames = map[int]string{
	SourceRunZero:               "runzero",
	SourceMiradore:              "miradore",
	SourceAWS:                   "aws",
	SourceCrowdStrike:           "crowdstrike",
	SourceAzure:                 "azure",
	SourceCensys:                "censys",
	SourceVMware:                "vmware",
	SourceGCP:                   "gcp",
	SourceSentinelOne:           "sentinelone",
	SourceTenable:               "tenable",
	SourceNessus:                "nessus",
	SourceNexpose:               "rapid7",
	SourceInsightVM:             "insightvm",
	SourceQualys:                "qualys",
	SourceShodan:                "shodan",
	SourceAzureAD:               "azuread",
	SourceLDAP:                  "ldap",
	SourceDefender365:           "ms365defender",
	SourceIntune:                "intune",
	SourceGoogleWorkspace:       "googleworkspace",
	SourceSample:                "sample",
	SourceCustom:                "custom",
	SourceTenableSecurityCenter: "tenablesecuritycenter",
	SourcePacket:                "packet",
	SourceWiz:                   "wiz",
	SourceMeraki:                "meraki",
	SourceMECM:                  "mecm",
	SourceTanium:                "tanium",
	SourceSimulator:             "simulator",
	SourceNetBox:                "netbox",
	SourceCIP:                   "cip",
	SourcePaloAltoNetworks:      "pan",
	SourcePaloAltoPrismaCloud:   "prisma",
	SourceDragos:                "dragos",
}
