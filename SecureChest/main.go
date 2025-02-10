// Objective : Create a secure chest to store password securely
// Author : xKayniT
// Date : 12/10/2023

package main

import (
	SecureChest "SecureChest/packages"
	"fmt"
)

func main() {
	master_func := SecureChest.MasterPass()
	if !master_func {
		fmt.Println("This message appeared because it is the first time you launch the program or a bad password was provided")
	} else if master_func {
		SecureChest.Display()
		var choix int
		_, choice_error := fmt.Scan(&choix)
		if choice_error != nil {
			panic("Error with the input user")
		}
		switch choix {
		case 1:
			SecureChest.AddEntry()
		case 2:
			SecureChest.ReadJson()
		case 3:
			SecureChest.DeleteEntry()
		case 4:
			SecureChest.CopyToClipboard()
		default:
			fmt.Println("This option is not available")
		}
	}

}
