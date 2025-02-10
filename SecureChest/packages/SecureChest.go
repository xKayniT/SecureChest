// Objective : Create a secure chest to store password securely
// Author : xKayniT
// Date : 12/10/2023

package SecureChest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"syscall"

	"os"

	"golang.design/x/clipboard"
	"golang.org/x/term"
)

type JSONStruct struct {
	Entries []struct {
		Login            string `json:"login"`
		Encoded_password string `json:"encoded_password"`
		Service          string `json:"service"`
	} `json:"entries"`
}

func Display() {
	fmt.Println("SecureChest, a secure chest developed in golang by xKayniT")
	fmt.Println("-----------------------")
	fmt.Println("1.Add an entry")
	fmt.Println("2.Show the content of an entry with the targeted service")
	fmt.Println("3.Delete an entry")
	fmt.Println("4.Copy service password to clipboard")
	fmt.Println("-----------------------")
}

func MasterPass() bool {
	master_file, _ := os.OpenFile(".master", os.O_CREATE|os.O_RDWR, 0600)
	defer master_file.Close()
	first_login := false
	check_if_empty, err := os.ReadFile(".master")
	if err != nil {
		panic("Error in opening master password file")
	} else if string(check_if_empty) == "" && !first_login {
		fmt.Println("Please define your master password : ")
		fmt.Println("Note : this is your master password if you lose it you won't have way to reset it")
		master_password, error_read := term.ReadPassword(int(syscall.Stdin))
		if master_password == nil || error_read != nil {
			panic("Error on the ReadPassword or empty password")
		}
		master_encoded := base64.StdEncoding.EncodeToString([]byte(master_password))
		_, error_write := master_file.Write([]byte(master_encoded))
		if error_write != nil {
			panic("Error with writing in file")
		}
	} else {
		fmt.Println("Please enter you master password : ")
		master_password, err := term.ReadPassword(int(syscall.Stdin))
		if master_password == nil || err != nil {
			panic("Error on the ReadPassword or empty password")
		}
		file_password, err := os.ReadFile(".master")
		if err != nil {
			panic("Error in opening master password file")
		}
		file_decoded_password, err := base64.StdEncoding.DecodeString(string(file_password))
		if err != nil {
			panic("Error in decoding master password from file")
		}
		if string(master_password) == string(file_decoded_password) {
			return true
		} else {
			return false
		}
	}
	return false
}

func AddEntry() {
	// Creation of the output file
	entry_file, _ := os.OpenFile("securechest.json", os.O_CREATE|os.O_RDWR, 0600)
	defer entry_file.Close()

	var login string
	fmt.Println("Fill the entry with your mail/login :")
	// Ask user for the mail/login
	_, login_scan_error := fmt.Scan(&login)
	if login_scan_error != nil {
		panic("Error with the input user")
	}
	fmt.Println("Fill the entry with your password : ")
	// Ask user for the password
	password, err := term.ReadPassword(int(syscall.Stdin))
	if password == nil || err != nil {
		panic("Error on the ReadPassword or empty password")
	}
	// Encode the password using base64 lib
	base64_encoded := base64.StdEncoding.EncodeToString([]byte(password))
	// Transform the data from uint8 to string
	strbcrypt := string(base64_encoded)

	var service string
	fmt.Println("Fill with the chosen service(Ex:gmail,youtube..) :")
	// Ask user for the targeted service
	_, service_scan_error := fmt.Scan(&service)
	if service_scan_error != nil {
		panic("Error with the input user")
	}

	jsonData, err := os.ReadFile("securechest.json")
	if err != nil {
		panic(err)
	}
	var jsonStruct JSONStruct
	if err := json.Unmarshal(jsonData, &jsonStruct); err != nil {
		// If the file is empty or not correct, initialize the JSON struct
		jsonStruct = JSONStruct{}
	}

	newEntry := struct {
		Login            string `json:"login"`
		Encoded_password string `json:"encoded_password"`
		Service          string `json:"service"`
	}{
		Login:            login,
		Encoded_password: strbcrypt,
		Service:          service,
	}
	jsonStruct.Entries = append(jsonStruct.Entries, newEntry)
	a_json, err := json.MarshalIndent(jsonStruct, "", " ")
	if err != nil {
		panic(err)
	}
	_, error_write := entry_file.Write(a_json)
	if error_write != nil {
		panic("Error with writing in file")
	}
}

func ReadJson() {
	content, err := os.ReadFile("securechest.json")
	if err != nil {
		panic(err)
	}

	var jsonStruct JSONStruct
	if err := json.Unmarshal(content, &jsonStruct); err != nil {
		panic(err)
	}

	var chosenservice string
	fmt.Println("Fill with the targeted service :")
	// Ask user for the mail/login
	_, service_scan_error := fmt.Scan(&chosenservice)
	if service_scan_error != nil {
		panic("Error with the input user")
	}
	for _, entry := range jsonStruct.Entries {
		if entry.Service == chosenservice {
			fmt.Println("Login:", entry.Login)
			fmt.Println("encoded_password:", entry.Encoded_password)
			fmt.Println("Service:", entry.Service)
		} else {
			fmt.Println("None entry corresponding to the specified service was found.")
		}
	}
}

func DeleteEntry() {
	jsonData, err := os.ReadFile("securechest.json")
	if err != nil {
		panic(err)
	}

	var jsonStruct JSONStruct
	if err := json.Unmarshal(jsonData, &jsonStruct); err != nil {
		panic(err)
	}

	var serviceToDelete string
	fmt.Println("Fill the service to delete :")
	_, service_scan_error := fmt.Scan(&serviceToDelete)
	if service_scan_error != nil {
		panic("Error with the input user")
	}

	// Search for the entry to delete
	indexToDelete := -1
	for i, entry := range jsonStruct.Entries {
		if entry.Service == serviceToDelete {
			indexToDelete = i
			break
		}
	}

	if indexToDelete == -1 {
		fmt.Println("None entry corresponding to the specified service was found.")
		return
	}

	// Deleting the corresponding entry of the array
	jsonStruct.Entries = append(jsonStruct.Entries[:indexToDelete], jsonStruct.Entries[indexToDelete+1:]...)

	// Rewrite JSON file with the new datas
	updatedData, err := json.MarshalIndent(jsonStruct, "", " ")
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("securechest.json", updatedData, 0600)
	if err != nil {
		panic(err)
	}

	fmt.Println("Entry deleted with success.")
}

func CopyToClipboard() {
	content, err := os.ReadFile("securechest.json")
	if err != nil {
		panic(err)
	}

	var jsonStruct JSONStruct
	if err := json.Unmarshal(content, &jsonStruct); err != nil {
		panic(err)
	}

	fmt.Println("Which service password do you want to copy :")
	var password_service string
	_, pass_scan_service := fmt.Scan(&password_service)
	if pass_scan_service != nil {
		panic("Error with the input user")
	}

	for _, entry := range jsonStruct.Entries {
		if entry.Service == password_service {
			decoded_password, err := base64.StdEncoding.DecodeString(entry.Encoded_password)
			if err != nil {
				panic("Error in decoding password")
			}
			clipboard.Write(clipboard.FmtText, []byte(decoded_password))
		} else {
			fmt.Println("None entry corresponding to the specified service was found.")
		}
	}
}
