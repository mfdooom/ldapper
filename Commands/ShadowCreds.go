package Commands

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"

	"github.com/go-ldap/ldap/v3"
)

type KeyCredential struct {
	Version  int
	KeyID    int
	KeyHash  string
	KeyValue string
	DeviceID uuid.UUID
}
type DNWithBinary struct {
	BinaryData        []byte
	DistinguishedName string
}

type entry struct {
	entryType int
	data      []byte
}

func ReadShadowCreds(baseDN string, conn *ldap.Conn) string {
	username := "dc1$"
	query := fmt.Sprintf("(samAccountName=%s)", username)
	searchReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, query, []string{}, nil)
	result, _ := conn.Search(searchReq)
	dnBinaryValue := result.Entries[0].GetRawAttributeValue("msDS-KeyCredentialLink")
	dnWithBinary, err := fromRawDNWithBinary(dnBinaryValue)
	if err != nil {
		fmt.Println(err)
	}
	key := fromDNWithBinary(dnWithBinary)
	fmt.Println(key)

	return "shadow"
}

func fromRawDNWithBinary(rawDNWithBinary []byte) (*DNWithBinary, error) {

	var dNWithBinary *DNWithBinary = new(DNWithBinary)

	colonCount := bytes.Count(rawDNWithBinary, []byte{0x3A})
	if colonCount != 3 {
		return dNWithBinary, errors.New("rawDNWithBinary should have exactly four parts separated by colons (:)")
	}

	size, _ := strconv.Atoi(string(bytes.Split(rawDNWithBinary, []byte{0x3A})[1]))
	binaryPart := bytes.Split(rawDNWithBinary, []byte{0x3A})[2]
	dn := bytes.Split(rawDNWithBinary, []byte{0x3A})[3]

	if len(binaryPart) != size {
		return dNWithBinary, errors.New("invalid BinaryData length. The length specified in the header does not match the data length")
	}
	binaryPart, _ = hex.DecodeString(string(binaryPart))
	dNWithBinary.BinaryData = binaryPart
	dNWithBinary.DistinguishedName = string(dn)

	return dNWithBinary, nil
}

func fromDNWithBinary(dNWithBinary *DNWithBinary) string {

	fmt.Printf("Length of dNWithBinary.BinaryData is %d\n", len(dNWithBinary.BinaryData))
	reader := bytes.NewReader(dNWithBinary.BinaryData)

	// read  4 bytes to get the version
	buf := make([]byte, 4)
	err := binary.Read(reader, binary.LittleEndian, buf)
	if err != nil {
		fmt.Println(err)
	}
	version := buf
	fmt.Printf("The version is %X\n", version)

	for reader.Len() >= 3 {
		buf := make([]byte, 3)
		err := binary.Read(reader, binary.LittleEndian, buf)
		if err != nil {
			fmt.Println(err)
		}

		length := binary.LittleEndian.Uint16(buf)
		entryType := int(buf[2])

		buf = make([]byte, length)
		err = binary.Read(reader, binary.LittleEndian, buf)
		if err != nil {
			fmt.Println(err)
		}

		var e entry
		e.entryType = entryType
		e.data = buf

		// testing GUID
		if e.entryType == 6 {
			fmt.Printf("devide id data: %x\n", e.data)
			deviceid, _ := uuid.FromBytes(e.data)
			fmt.Printf("The device ID is %s\n", deviceid.String())
		}

	}

	/*
		buf = make([]byte, 3)
		err = binary.Read(reader, binary.LittleEndian, buf)
		if err != nil {
			fmt.Println(err)
		}



	*/
	return ""

}
