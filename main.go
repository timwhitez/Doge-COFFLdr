package main

import (
	"fmt"
	"github.com/timwhitez/Doge-COFFLdr/pkg/coff"
	"io/ioutil"
	"log"
	"os"
	"syscall"
	"unsafe"
)

var Glob_Token uintptr = 0

func main() {
	coff.SetGlobToken(Glob_Token)

	rawCoff, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	var config []byte

	if len(os.Args) == 3 {
		config, _ = ioutil.ReadFile(os.Args[2])
	}

	outdata, err := coff.LoadAndRun(rawCoff, config)

	if outdata != "" {
		fmt.Printf("Outdata Below:\n\n%s\n", outdata)
	}
	if err != nil {
		fmt.Errorf("Error Msg:\n\n%s\n", err)
	}

	Glob_Token = coff.GetGlobToken()

	fmt.Println(Glob_Token)
	fmt.Println(getTokenUsername(Glob_Token))

	createNewtoken("C:\\Windows\\System32\\notepad.exe")

}

func createNewtoken(cmdl string) {

	var (
		si syscall.StartupInfo
		pi syscall.ProcessInformation
	)

	commandLine, _ := syscall.UTF16PtrFromString(cmdl)

	si.Cb = uint32(unsafe.Sizeof(syscall.StartupInfo{}))

	CreateProcessWithTokenW := syscall.NewLazyDLL("Advapi32").NewProc("CreateProcessWithTokenW")
	CreateProcessWithTokenW.Call(
		Glob_Token,
		0x00000002,
		0,
		uintptr(unsafe.Pointer(commandLine)),
		0x00000010,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

}

var (
	advapi32                = syscall.NewLazyDLL("advapi32.dll")
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
	procLookupAccountSid    = advapi32.NewProc("LookupAccountSidA")
)

// TokenUser struct
type TOKEN_USER struct {
	User syscall.SIDAndAttributes
}

func getTokenUsername(token uintptr) string {
	// 定义变量
	var TokenUserInfo TOKEN_USER
	var returned_tokinfo_length uint32
	username_only := make([]byte, 256)
	domainname_only := make([]byte, 256)
	var usernameSize = uint32(unsafe.Sizeof(username_only))
	var domainSize = uint32(unsafe.Sizeof(domainname_only))
	var sidType uint32

	// 调用GetTokenInformation
	success, _, _ := procGetTokenInformation.Call(
		token,
		uintptr(syscall.TokenUser), // TokenUser
		uintptr(unsafe.Pointer(&TokenUserInfo)),
		4096,
		uintptr(unsafe.Pointer(&returned_tokinfo_length)))

	if success == 0 {
		return ""
	}

	// 调用LookupAccountSid
	success, _, _ = procLookupAccountSid.Call(
		0,
		uintptr(unsafe.Pointer(TokenUserInfo.User.Sid)),
		uintptr(unsafe.Pointer(&username_only[0])),
		uintptr(unsafe.Pointer(&usernameSize)),
		uintptr(unsafe.Pointer(&domainname_only[0])),
		uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&sidType)))

	if success == 0 {
		return ""
	}

	return fmt.Sprintf("%s\\%s\n", string(domainname_only[:domainSize]), string(username_only[:usernameSize]))
}
