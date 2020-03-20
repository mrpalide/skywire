package appcommon

// Config defines configuration parameters for `Proc`.
type Config struct {
	Name       string `json:"name"`
	ServerAddr string `json:"server_addr"`
	VisorPK    string `json:"visor_pk"`
	BinaryDir  string `json:"binary_dir"`
	WorkDir    string `json:"work_dir"`
}
