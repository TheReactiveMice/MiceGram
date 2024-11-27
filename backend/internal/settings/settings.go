package settings

import (
	"bytes"
	"encoding/json"
	"os"
	"pizdec/internal/ipc"
)

type Settings struct {
	Hostname string `json:"hostname"`
	Port     int32  `json:"port"`
	Visible  bool   `json:"visible"`

	Profile *ipc.UserProfile `json:"profile"`
}

func SaveSettings(settings Settings, filename string) error {
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)

	if err := encoder.Encode(settings); err != nil {
		return err
	}

	if err := os.WriteFile(filename, buffer.Bytes(), 0777); err != nil {
		return err
	}

	return nil
}

func LoadSettings(filename string) (Settings, error) {
	buffer := new(Settings)
	file, err := os.ReadFile(filename)

	if err != nil {
		return Settings{}, err
	}

	if err := json.Unmarshal(file, &buffer); err != nil {
		return Settings{}, err
	}

	return *buffer, nil
}
