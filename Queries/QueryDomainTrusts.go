package Queries

import (
	"fmt"
	"ldapper/Globals"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var trustAttributes = map[int]string{
	0x00000001: "NON_TRANSITIVE",
	0x00000002: "UPLEVEL_ONLY",
	0x00000004: "FILTER_SIDS",
	0x00000008: "FOREST_TRANSITIVE",
	0x00000010: "CROSS_ORGANIZATION",
	0x00000020: "WITHIN_FOREST",
	0x00000040: "TREAT_AS_EXTERNAL",
	0x00000080: "TRUST_USES_RC4_ENCRYPTION",
	0x00000100: "TRUST_USES_AES_KEYS",
	0x00000200: "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
	0x00000400: "PIM_TRUST",
}

var trustTypeMap = map[int]string{
	1: "WINDOWS_NON_ACTIVE_DIRECTORY",
	2: "WINDOWS_ACTIVE_DIRECTORY",
	3: "MIT",
}

var trustDirectionMap = map[int]string{
	0: "Disabled",
	1: "Inbound",
	2: "Outbound",
	3: "Bidirectional",
}

func GetDomainTrusts(baseDN string, conn *ldap.Conn) (queryResult string) {

	query := "(objectClass=trustedDomain)"         // Build the query
	searchReq := Globals.LdapSearch(baseDN, query) // Search the baseDN
	result, err := conn.Search(searchReq)          // Execute the search
	if err != nil {
		fmt.Printf("Query error, %s", err)
	}

	for i := range result.Entries {
		distinguishedName := result.Entries[i].GetAttributeValues("distinguishedName")[0]
		trustAttribute, err := strconv.Atoi(result.Entries[i].GetAttributeValues("trustAttributes")[0])
		trustType, err := strconv.Atoi(result.Entries[i].GetAttributeValues("trustType")[0])
		trustDirection, err := strconv.Atoi(result.Entries[i].GetAttributeValues("trustDirection")[0])
		whenCreated, err := time.Parse("20060102150405Z", result.Entries[i].GetAttributeValues("whenCreated")[0])
		whenChanged, err := time.Parse("20060102150405Z", result.Entries[i].GetAttributeValues("whenChanged")[0])
		if err != nil {
			fmt.Printf("Error reading LDAP Result: %s", err)
		}

		sourceDomainIndex := strings.Index(distinguishedName, "DC=")
		destDomainIndex := strings.Index(distinguishedName, ",CN=System")

		destDomain := string(distinguishedName[3:destDomainIndex])

		sourceDomain := strings.ReplaceAll(strings.ReplaceAll(distinguishedName[sourceDomainIndex:len(distinguishedName)], "DC=", ""), ",", ".")

		queryResult += fmt.Sprintf("SourceDomain: \t%s\n", sourceDomain)
		queryResult += fmt.Sprintf("TargetDomain: \t%s\n", destDomain)
		queryResult += fmt.Sprintf("TrustType: \t%s\n", trustTypeMap[trustType])

		queryResult += fmt.Sprintf("TrustAttributes: ")
		for code, _ := range trustAttributes {
			if (code & trustAttribute) > 0 {
				queryResult += fmt.Sprintf("\t%s\n", trustAttributes[code])
			}
		}

		queryResult += fmt.Sprintf("TrustDirection: \t%s\n", trustDirectionMap[trustDirection])
		queryResult += fmt.Sprintf("WhenCreated: \t%s\n", whenCreated)
		queryResult += fmt.Sprintf("WhenChanged: \t%s\n", whenChanged)
	}

	return queryResult
}
