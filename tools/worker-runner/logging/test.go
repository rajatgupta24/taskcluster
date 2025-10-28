package logging

import (
	"sync"

	"github.com/taskcluster/taskcluster/v91/tools/worker-runner/logging/logging"
)

type TestLogDestination struct {
	mutex    sync.Mutex
	messages []map[string]any
}

func (dst *TestLogDestination) Messages() []map[string]any {
	dst.mutex.Lock()
	messages := dst.messages
	dst.mutex.Unlock()
	return messages
}

func (dst *TestLogDestination) Clear() {
	dst.mutex.Lock()
	dst.messages = []map[string]any{}
	dst.mutex.Unlock()
}

func (dst *TestLogDestination) LogUnstructured(message string) {
	dst.mutex.Lock()
	dst.messages = append(dst.messages, logging.ToStructured(message))
	dst.mutex.Unlock()
}

func (dst *TestLogDestination) LogStructured(message map[string]any) {
	dst.mutex.Lock()
	dst.messages = append(dst.messages, message)
	dst.mutex.Unlock()
}
