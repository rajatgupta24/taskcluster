package logging

import (
	"github.com/taskcluster/taskcluster/v91/tools/worker-runner/logging"
	"github.com/taskcluster/taskcluster/v91/tools/workerproto"
)

func SetProtocol(proto *workerproto.Protocol) {
	// Register to receive log messages on the given protocol
	proto.AddCapability("log")
	proto.Register("log", func(msg workerproto.Message) {
		body, ok := msg.Properties["body"]
		if ok {
			logging.Destination.LogStructured(body.(map[string]any))
		} else {
			logging.Destination.LogUnstructured("received log message from worker lacking 'body' property")
		}
	})
}
