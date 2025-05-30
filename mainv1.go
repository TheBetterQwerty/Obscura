package main

import (
        "encoding/csv"
        "encoding/gob"
        "fmt"
        "log"
        "math/rand"
        "module/mymodule"
        "os"
        "strings"
        "syscall"

        "golang.org/x/term"
)

const (
        PATH         = "/home/qwerty/.passmanager"
        DUMPFILE     = "/home/qwerty/.passmanager/dump.bin"
        PASSWORDFILE = "/home/qwerty/.passmanager/pass.bin"
        EXPORTFILE   = "/home/qwerty/Desktop/datadump.csv"
)

type Entries struct {
        Site     string
        Username string
        Password string
        Note     string
}

func Dump(list []Entries) error {
        file, err := os.Create(PASSWORDFILE)
        if err != nil {
                return err
        }
        defer file.Close()

        enc := gob.NewEncoder(file)
        err = enc.Encode(list)
        return err
}

func Load() ([]Entries, error) {
        file, err := os.Open(PASSWORDFILE)
        if err != nil {
                return nil, err
        }
        defer file.Close()

        var list []Entries
        dec := gob.NewDecoder(file)
        err = dec.Decode(&list)
        if err != nil {
                if err.Error() == "EOF" {
                        return nil, nil
                }
                return nil, err
        }
        return list, nil
}

func contains(str string, substr string) bool {
        if len(substr) > len(str) {
                return false
        }

        for i := 0; i <= len(str)-len(substr); i++ {
                var cnt int = 0
                for j := 0; j < len(substr); j++ {
                        if strings.ToUpper(string(str[i+j])) != strings.ToUpper(string(substr[j])) {
                                break
                        }
                        cnt++
                }
                if cnt == len(substr) {
                        return true
                }
        }
        return false
}

func encrypt_info(entry Entries, hashed_password []byte) Entries {
        local, _ := mymodule.Encrypt([]byte(entry.Site), hashed_password)
        entry.Site = string(local)
        local, _ = mymodule.Encrypt([]byte(entry.Username), hashed_password)
        entry.Username = string(local)
        local, _ = mymodule.Encrypt([]byte(entry.Password), hashed_password)
        entry.Password = string(local)
        local, _ = mymodule.Encrypt([]byte(entry.Note), hashed_password)
        entry.Note = string(local)
        return entry
}

func decrypt_info(content Entries, hashed_password []byte) Entries {
        var entry Entries
        local, _ := mymodule.Decrypt([]byte(content.Site), hashed_password)
        entry.Site = string(local)
        local, _ = mymodule.Decrypt([]byte(content.Username), hashed_password)
        entry.Username = string(local)
        local, _ = mymodule.Decrypt([]byte(content.Password), hashed_password)
        entry.Password = string(local)
        local, _ = mymodule.Decrypt([]byte(content.Note), hashed_password)
        entry.Note = string(local)
        return entry
}

func import_passwords(password string) {
        var temp Entries
        var filename string

        fmt.Printf("[?] Enter Name of File -> ")
        fmt.Scanln(&filename)

        file_contents, err := os.Open(filename)
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }
        defer file_contents.Close()

        csv_reader := csv.NewReader(file_contents)
        string_contents, err := csv_reader.ReadAll()
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }

        string_contents = string_contents[1:] // 1st line has headers like username password
        hashed_password := mymodule.Hash256(password)

        // Load passwords
        file_content, err := Load()
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }

        // Encrypt data
        for _, content := range string_contents {
                temp.Site = content[0]
                temp.Username = content[1]
                temp.Password = content[2]
                temp.Note = content[3]
                enc_temp := encrypt_info(temp, hashed_password)
                file_content = append(file_content, enc_temp)
        }

        // Dump
        err = Dump(file_content)
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }
        fmt.Printf("[*] Imported %v Passwords from %v!\n", len(string_contents), filename)
}

func export_passwords(password string) {
        var string_contents [][]string
        var temp Entries

        hashed_password := mymodule.Hash256(password)
        file_contents, err := Load()
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
        }

        string_contents = append(string_contents, []string{"Site", "Username", "Password", "Note"}) // Header
        for _, content := range file_contents {
                temp = decrypt_info(content, hashed_password)
                string_contents = append(string_contents, []string{temp.Site, temp.Username, temp.Password, temp.Note})
        }

        file, err := os.Create(EXPORTFILE)
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
        }

        w := csv.NewWriter(file)
        w.WriteAll(string_contents)
        log.Printf("[*] Exported passwords to %v!\n", EXPORTFILE)
}

func edit_existing_password(password string) {
        var search string
        var new_entry, found_entry Entries
        found := -1

        hashed_password := mymodule.Hash256(password)
        file_contents, err := Load()
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }

        fmt.Printf("[?] Enter Site or Username to Search -> ")
        fmt.Scanln(&search)

        // Decrypting
        for i, content := range file_contents {
                file_contents[i] = decrypt_info(content, hashed_password)
                if contains(file_contents[i].Username, search) || contains(file_contents[i].Site, search) {
                        found_entry = file_contents[i]
                        found = i
                }
        }

        if found == -1 {
                fmt.Printf("[!] No Records Found !\n")
                return
        }

        fmt.Printf("[*] Record Found!\n")

        fmt.Printf("[?] Enter new Site name -> ")
        fmt.Scanln(&new_entry.Site)
        if len(new_entry.Site) == 0 {
                new_entry.Site = found_entry.Site
        }
        fmt.Printf("[?] Enter new Username -> ")
        fmt.Scanln(&new_entry.Username)
        if len(new_entry.Username) == 0 {
                new_entry.Username = found_entry.Username
        }
        fmt.Printf("[?] Enter new Password  -> ")
        fmt.Scanln(&new_entry.Password)
        if len(new_entry.Password) == 0 {
                new_entry.Password = found_entry.Password
        }
        fmt.Printf("[?] Enter New Note -> ")
        fmt.Scanln(&new_entry.Note)
        if len(new_entry.Note) == 0 {
                new_entry.Note = found_entry.Note
        }

        file_contents[found] = new_entry
        // Encrypting
        for i, content := range file_contents {
                file_contents[i] = encrypt_info(content, hashed_password)
        }

        if err := Dump(file_contents); err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }
        fmt.Printf("[*] Record Edited!\n")
}

func delete_password(password string) {
        var search string
        found := false
        var new_entry []Entries
        var confirmation string

        hash_password := mymodule.Hash256(password)
        file_contents, err := Load()
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }

        // Decrypting
        for i, content := range file_contents {
                file_contents[i] = decrypt_info(content, hash_password)
        }

        fmt.Printf("[?] Enter site or username to be deleted -> ")
        fmt.Scanln(&search)
        for _, file := range file_contents {
                if file.Site == search || file.Username == search {
                        found = true
                        fmt.Printf("[*] Record Found!\n")
                        fmt.Printf("[*] Do You Want to Delete it (Y/N) ?")
                        fmt.Scanln(&confirmation)
                        break
                }
        }

        if confirmation[0] != 'Y' && confirmation[0] != 'y' {
                fmt.Printf("[-] Record Not Deleted!\n")
                return
        }

        for _, file := range file_contents {
                if file.Site != search && file.Username != search {
                        file = encrypt_info(file, hash_password)
                        new_entry = append(new_entry, file)
                }
        }
        fmt.Printf("[*] Record Deleted!\n")
        if err := Dump(new_entry); err != nil {
                log.Printf("[!] Error: %v\n", err)
        }

        if !found {
                fmt.Printf("[!] Record Not Found !\n")
        }
}

func generate_random_password() string {
        var password string
        chars := `G4$eJ#8dLpOaR1TbMnIcKfE"hN5gY6xZC9wS7qVrU3sD2tB!P0_F-]i@j+{=k;l'A8H6o*m%&^)9(_+QWzXv`
        for i := 0; i < 30; i++ {
                random_index := rand.Intn(83)
                password += string(chars[random_index])
        }
        return password
}

func view_saved_passwords(password string) {
        // Logic For First time
        if _, err := os.Stat(PASSWORDFILE); os.IsNotExist(err) {
                _, err := os.Create(PASSWORDFILE)
                if err != nil {
                        log.Printf("[!] Error Creating password file\n")
                        return
                }

                log.Printf("[*] No Password File found.\n")
                return
        } else if err != nil {
                log.Printf("%v\n", err) // Permission error etc
                return
        }

        // Logic if not first time
        filecontent, err := Load()
        if err != nil {
                log.Printf("%v\n", err)
                return
        }

        hashed_password := mymodule.Hash256(password)

        // Decrypting all the passwords
        var new_contents []Entries
        for _, content := range filecontent {
                entry := decrypt_info(content, hashed_password)
                new_contents = append(new_contents, entry)
        }

        var search string
        flag := -1
        fmt.Printf("| [?] Enter the site or the username -> ")
        fmt.Scanln(&search)

        for _, content := range new_contents {
                if contains(content.Site, search) || contains(content.Username, search) {
                        fmt.Printf("+-------------------------------------------------+\n")
                        fmt.Printf("| Site :      %v\n", content.Site)
                        fmt.Printf("| Username :  %v\n", content.Username)
                        fmt.Printf("| Password :  %v\n", content.Password)
                        if content.Note != "" {
                                fmt.Printf("| Note :      %v\n", content.Note)
                        }
                        flag++
                }
        }
        if flag == -1 {
                fmt.Printf("| [!] No Record Was Found!\n")
                return
        }
        fmt.Printf("+-------------------------------------------------+\n")
}

func add_new_passwords(password string) {
        var entry Entries
        // Input
        fmt.Printf("Site : ")
        fmt.Scanln(&entry.Site)
        fmt.Printf("Username : ")
        fmt.Scanln(&entry.Username)
        fmt.Printf("Password (if empty generates a safe password) : ")
        fmt.Scanln(&entry.Password)
        if len(entry.Password) == 0 {
                entry.Password = generate_random_password()
                fmt.Printf("Generated Password -> %v\n", entry.Password)
        }
        fmt.Printf("Note : ")
        fmt.Scanln(&entry.Note)
        hashed_password := mymodule.Hash256(password)

        // Encrypt
        enc_entry := encrypt_info(entry, hashed_password)

        // loading
        Entries_from_file, err := Load()
        if err != nil {
                log.Printf("%v\n", err)
        }
        Entries_from_file = append(Entries_from_file, enc_entry)

        if err := Dump(Entries_from_file); err != nil {
                log.Printf("%v\n", err)
        }
        fmt.Printf("[+] Password Was Stored!\n")
}

func change_password() {
        fmt.Printf("[?] Enter Your Current Password: ")
        password, err := get_password_securely()
        if err != nil {
                fmt.Printf("[!] Error %s\n", err)
        }

        if !check_password(password) {
                fmt.Printf("[!] Error passwords dont match!\n")
                return
        }

        hash_password := mymodule.Hash256(password)
        password = ""
        file_contents, err := Load()
        if err != nil {
                log.Printf("Error: %v\n", err)
                return
        }

        fmt.Printf("[?] Enter Your New Password: ")
        password, _ = get_password_securely()
        fmt.Printf("[?] Enter Your Password Again: ")
        passwd, _ := get_password_securely()

        if passwd != password {
                fmt.Printf("[!] Passwords Dont Match!\n")
                return
        }

        new_hash_password256 := mymodule.Hash256(passwd)
        new_hash_password512 := mymodule.Hash512(passwd)
        for idx, contents := range file_contents {
                temp := decrypt_info(contents, hash_password)
                file_contents[idx] = encrypt_info(temp, new_hash_password256)
        }

        err = Dump(file_contents)
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }

        file, err := os.OpenFile(DUMPFILE, os.O_RDWR|os.O_TRUNC, 0600)
        if err != nil {
                log.Printf("[!] Error %v\n", err)
                return
        }

        file.WriteString(new_hash_password512)
        fmt.Printf("[+] Password Changed Sucessfully!\n")
}

func menu(password string) {
        var choice int
        fmt.Println("+---------------------------------+")
        fmt.Println("|      Password Manager Menu      |")
        fmt.Println("+---------------------------------+")
        fmt.Println("| 1. View Saved Passwords         |")
        fmt.Println("| 2. Add New Password             |")
        fmt.Println("| 3. Generate Password            |")
        fmt.Println("| 4. Delete Password              |")
        fmt.Println("| 5. Edit Existing Password       |")
        fmt.Println("| 6. Import Password From File    |")
        fmt.Println("| 7. Export Passwords             |")
        fmt.Println("| 8. Change Password              |")
        fmt.Println("| 9. Exit Password Manager        |")
        fmt.Println("+---------------------------------+")

        fmt.Print("| [?] Enter Choice: ")
        fmt.Scanln(&choice)

        switch choice {
        case 1:
                view_saved_passwords(password)
        case 2:
                add_new_passwords(password)
        case 3:
                fmt.Printf("[+] Generated random password -> %v\n", generate_random_password())
        case 4:
                delete_password(password)
        case 5:
                edit_existing_password(password)
        case 6:
                import_passwords(password)
        case 7:
                export_passwords(password)
        case 8:
                change_password()
        default:
                fmt.Printf("Bye\n")
                return
        }
}

func check_password(password string) bool {
        data, err := os.ReadFile(DUMPFILE)
        if err != nil {
                panic(fmt.Sprintf("Error: %v", err))
        }

        actual_hash_password := string(data)
        hash_password := mymodule.Hash512(password)

        return hash_password == actual_hash_password
}

func create_database_password() {
        fmt.Printf("[?] Enter Your DataBase Password: ")
        password, err := get_password_securely()
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }
        fmt.Printf("[?] Enter Your DataBase Password Again: ")
        _password, err := get_password_securely()
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }

        if password != _password {
                fmt.Printf("[!] Passwords Dont Match!!\n")
                return
        }

        // Creating the folder
        err = os.MkdirAll(PATH, 0700)
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }

        _, err = os.Create(PASSWORDFILE)
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }

        hash_password := mymodule.Hash512(password)

        file, err := os.Create(DUMPFILE)
        if err != nil {
                log.Printf("[!] Error: %v\n", err)
                return
        }
        defer file.Close()

        // Writting to the file
        file.WriteString(string(hash_password))
        fmt.Printf("[+] Password Saved Sucessfully \n")
}

func get_password_securely() (string, error) {
        byte_password, err := term.ReadPassword(int(syscall.Stdin))
        fmt.Printf("\n")
        if err != nil {
                return "", err
        }
        password := string(byte_password)
        return strings.TrimSpace(password), nil
}

func main() {
        if _, err := os.Stat(DUMPFILE); os.IsNotExist(err) {
                create_database_password()
                return
        }

        for i := 0; i < 5; i++ {
                fmt.Printf("[?] Enter Your Password: ")
                password, err := get_password_securely()
                if err != nil {
                        log.Printf("[!] Error: %v\n", err)
                }

                if check_password(password) {
                        menu(password)
                        return
                }
                fmt.Printf("[!] You Have %v Tries Left\n", 5-(i+1))
        }
}
