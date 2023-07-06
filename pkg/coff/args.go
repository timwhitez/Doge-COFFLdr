package coff

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/text/encoding/unicode"
)

func ParseArgs(args []BofArgs) ([]byte, int, error) {
	var err error

	bofA := BOFArgsBuffer{
		Buffer: new(bytes.Buffer),
	}

	for _, a := range args {
		switch a.ArgType {
		case "integer":
			fallthrough
		case "int":
			if v, ok := a.Value.(float64); ok {
				err = bofA.AddInt(uint32(v))
			}
		case "string":
			if v, ok := a.Value.(string); ok {
				err = bofA.AddString(v)
			}
		case "wstring":
			if v, ok := a.Value.(string); ok {
				err = bofA.AddWString(v)
			}
		case "short":
			if v, ok := a.Value.(float64); ok {
				err = bofA.AddShort(uint16(v))
			}
		case "binary":
			if v, ok := a.Value.([]byte); ok {
				err = bofA.AddData([]byte(v))
			}
		}
		if err != nil {
			return nil, 0, err
		}
	}
	parsedArgs, argsSize, err := bofA.GetBuffer()
	if err != nil {
		return nil, 0, err
	}

	return parsedArgs, argsSize, nil

}

type BofArgs struct {
	ArgType string      `json:"type"`
	Value   interface{} `json:"value"`
}
type BOFArgsBuffer struct {
	Buffer *bytes.Buffer
}

func (b *BOFArgsBuffer) AddData(d []byte) error {
	dataLen := uint32(len(d))
	err := binary.Write(b.Buffer, binary.LittleEndian, &dataLen)
	if err != nil {
		return err
	}
	return binary.Write(b.Buffer, binary.LittleEndian, &d)
}

func (b *BOFArgsBuffer) AddShort(d uint16) error {
	return binary.Write(b.Buffer, binary.LittleEndian, &d)
}

func (b *BOFArgsBuffer) AddInt(d uint32) error {
	return binary.Write(b.Buffer, binary.LittleEndian, &d)
}

func (b *BOFArgsBuffer) AddString(d string) error {
	stringLen := uint32(len(d)) + 1
	err := binary.Write(b.Buffer, binary.LittleEndian, &stringLen)
	if err != nil {
		return err
	}
	dBytes := append([]byte(d), 0x00)
	return binary.Write(b.Buffer, binary.LittleEndian, dBytes)
}

func (b *BOFArgsBuffer) AddWString(d string) error {
	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	strBytes := append([]byte(d), 0x00)
	utf16Data, err := encoder.Bytes(strBytes)
	if err != nil {
		return err
	}
	stringLen := uint32(len(utf16Data))
	err = binary.Write(b.Buffer, binary.LittleEndian, &stringLen)
	if err != nil {
		return err
	}
	return binary.Write(b.Buffer, binary.LittleEndian, utf16Data)
}

func (b *BOFArgsBuffer) GetBuffer() ([]byte, int, error) {
	outBuffer := new(bytes.Buffer)
	Size := b.Buffer.Len()
	err := binary.Write(outBuffer, binary.LittleEndian, uint32(b.Buffer.Len()))
	if err != nil {
		return nil, 0, err
	}
	err = binary.Write(outBuffer, binary.LittleEndian, b.Buffer.Bytes())
	if err != nil {
		return nil, 0, err
	}
	return outBuffer.Bytes(), Size, nil
}
