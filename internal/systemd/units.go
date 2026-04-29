package systemd

import _ "embed"

//go:embed certmaid.service
var ServiceUnit []byte

//go:embed certmaid.timer
var TimerUnit []byte