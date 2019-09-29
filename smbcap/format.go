package smbcap

// Format describes a set of names for SMB capability flags.
type Format map[Flags]string

// ProtoNames maps individual flags to their names as defined by the SMB
// protocol specification.
var ProtoNames = Format{
	DFS:               "SMB2_GLOBAL_CAP_DFS",
	Leasing:           "SMB2_GLOBAL_CAP_LEASING",
	LargeMTU:          "SMB2_GLOBAL_CAP_LARGE_MTU",
	MultiChannel:      "SMB2_GLOBAL_CAP_MULTI_CHANNEL",
	PersistentHandles: "SMB2_GLOBAL_CAP_PERSISTENT_HANDLES",
	DirectoryLeasing:  "SMB2_GLOBAL_CAP_DIRECTORY_LEASING",
	Encryption:        "SMB2_GLOBAL_CAP_ENCRYPTION",
}

// GoNames maps individual flags to their Go-style names.
var GoNames = Format{
	DFS:               "DFS",
	Leasing:           "Leasing",
	LargeMTU:          "LargeMTU",
	MultiChannel:      "MultiChannel",
	PersistentHandles: "PersistentHandles",
	DirectoryLeasing:  "DirectoryLeasing",
	Encryption:        "Encryption",
}
