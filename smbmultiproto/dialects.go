package smbmultiproto

import (
	"github.com/gentlemanautomaton/smb/smbdialect"
)

const (
	smbWildcard = "SMB 2.???"
	smb2002     = "SMB 2.002"
)

var (
	dialectBoth     = dialectList(smbdialect.Wildcard, smbdialect.SMB202)
	dialectWildcard = dialectList(smbdialect.Wildcard)
	dialectSMB202   = dialectList(smbdialect.SMB202)
)

func dialectList(members ...smbdialect.Revision) smbdialect.List {
	list := make(smbdialect.List, len(members)*2)
	for i := range members {
		list.SetMember(i, members[i])
	}
	return list
}
