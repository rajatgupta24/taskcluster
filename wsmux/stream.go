package wsmux

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// DefaultCapacity of read buffer of stream
	DefaultCapacity = 1024
)

/*Stream States:
created = stream has been created. Buffer is empty. Has not been accepted.
accepted = stream has been accepted. read write operations permitted.
closed = stream has been closed.
remoteClosed = remote side has been closed.
dead = closed & remoteClosed. Buffer may still have data.
*/
type streamState int

const (
	created streamState = iota
	accepted
	closed
	remoteClosed
	dead
)

type stream struct {
	id uint32     // id of the stream. Used for logging.
	m  sync.Mutex // mutex for state transitions
	c  *sync.Cond // used for broadcasting when closed, data read, or data pushed to buffer
	b  *buffer    // read buffer

	unblocked uint32 // number of bytes that can be sent to remote

	endErr   error         // error causes stream to close
	state    streamState   // current state of the stream
	accepted chan struct{} // closed when stream is accepted. Used in session.Open()

	session *Session // assosciated session. used for sending frames and logging

	readTimer             *time.Timer // timer for read operations
	writeTimer            *time.Timer // timer for write operations
	readDeadlineExceeded  bool        // true when readTimer fires
	writeDeadlineExceeded bool        // true when writeTimer fires
}

func newStream(id uint32, session *Session) *stream {
	str := &stream{
		id:        id,
		b:         newBuffer(DefaultCapacity),
		unblocked: 0,
		state:     created,
		accepted:  make(chan struct{}),

		endErr: nil,

		readTimer:             nil,
		writeTimer:            nil,
		readDeadlineExceeded:  false,
		writeDeadlineExceeded: false,

		session: session,
	}

	str.c = sync.NewCond(&str.m)

	return str
}

// HandleFrame processes frames received by the stream
func (s *stream) HandleFrame(fr frame) {
	switch fr.msg {
	case msgACK:
		// if not accepted then close accepted channel, otherwise unblock
		read := binary.LittleEndian.Uint32(fr.payload)
		select {
		case <-s.accepted:
			s.UnblockAndBroadcast(read)
		default:
			s.AcceptStream(read)
		}
	case msgDAT:
		s.session.logger.Printf("stream %d received DAT frame: %v", s.id, fr)
		s.PushAndBroadcast(fr.payload)
	case msgFIN:
		s.session.logger.Printf("remote stream %d closed connection", s.id)
		s.setRemoteClosed()
	}
}

// onExpired is an internal helper method which sets val = true and broadcasts
func (s *stream) onExpired(val *bool) func() {
	return func() {
		s.m.Lock()
		defer s.m.Unlock()
		defer s.c.Broadcast()
		*val = true
	}
}

// SetReadDeadline sets the read timer
func (s *stream) SetReadDeadline(t time.Time) error {

	s.m.Lock()
	defer s.m.Unlock()
	// stop timer if not nil
	if s.readTimer != nil {
		_ = s.readTimer.Stop()
		s.readTimer = nil
	}
	// clear deadline exceeded
	s.readDeadlineExceeded = false
	if !t.IsZero() {
		delay := t.Sub(time.Now())
		s.readTimer = time.AfterFunc(delay, s.onExpired(&s.readDeadlineExceeded))
	}

	return nil
}

// SetWriteDeadline sets the write timer
func (s *stream) SetWriteDeadline(t time.Time) error {
	s.m.Lock()
	defer s.m.Unlock()
	//stop timer if not nil
	if s.writeTimer != nil {
		_ = s.writeTimer.Stop()
		s.writeTimer = nil
	}
	// clear deadline exceeded
	s.writeDeadlineExceeded = false
	if !t.IsZero() {
		delay := t.Sub(time.Now())
		s.writeTimer = time.AfterFunc(delay, s.onExpired(&s.writeDeadlineExceeded))
	}

	return nil
}

// UnblockAndBroadcast unblocks bytes and broadcasts so that writes can
// continue
func (s *stream) UnblockAndBroadcast(read uint32) {
	s.m.Lock()
	defer s.m.Unlock()
	defer s.c.Broadcast()
	defer s.session.logger.Printf("unblock broadcasted : stream %d", s.id)
	s.unblocked += read
}

// PushAndBroadcast adds data to the read buffer and broadcasts so that
// reads can continue
func (s *stream) PushAndBroadcast(buf []byte) {
	s.m.Lock()
	defer s.m.Unlock()
	defer s.c.Broadcast()
	defer s.session.logger.Printf("push broadcasted : stream %d", s.id)
	_, err := s.b.Write(buf)
	s.endErr = err
}

// AcceptStream accepts the current stream by closing the accepted channel
func (s *stream) AcceptStream(read uint32) {
	s.m.Lock()
	defer s.m.Unlock()
	defer s.c.Broadcast()
	s.unblocked += read
	s.state = accepted
	close(s.accepted)

}

// SetDeadline sets the read and write deadlines for the stream
func (s *stream) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		s.endErr = err
		return err
	}
	if err := s.SetWriteDeadline(t); err != nil {
		s.endErr = err
		return err
	}
	return nil
}

func (s *stream) IsRemovable() bool {
	s.m.Lock()
	defer s.m.Unlock()
	return s.state == dead && s.b.Len() == 0
}

// setRemoteClosed sets the value of stream.remoteClosed. This indicates that the remote has sent a fin packet
func (s *stream) setRemoteClosed() {
	s.m.Lock()
	defer s.m.Unlock()
	defer s.c.Broadcast()
	if s.state == closed {
		s.state = dead
	} else {
		s.state = remoteClosed
	}
}

//LocalAddr returns the local address of the underlying connection
func (s *stream) LocalAddr() net.Addr {
	return s.session.conn.LocalAddr()
}

// RemoteAddr returns the remote address of the underlying connection
func (s *stream) RemoteAddr() net.Addr {
	return s.session.conn.RemoteAddr()
}

// Close closes the stream
func (s *stream) Close() error {
	s.m.Lock()
	defer s.m.Unlock()
	defer s.c.Broadcast()

	switch s.state {
	// return nil if already closed
	case closed:
		return nil
	case remoteClosed:
		s.state = dead
	default:
		s.state = closed
	}

	if err := s.session.send(newFinFrame(s.id)); err != nil {
		return err
	}

	return nil
}

// Read reads bytes from the stream
func (s *stream) Read(buf []byte) (int, error) {
	s.m.Lock()
	defer s.m.Unlock()
	defer s.c.Broadcast()

	s.session.logger.Printf("stream %d: read requested", s.id)

	for s.b.Len() == 0 && s.endErr == nil && !s.readDeadlineExceeded && s.state != remoteClosed && s.state != dead {
		s.session.logger.Printf("stream %d: read waiting", s.id)
		// wait
		s.c.Wait()
	}

	// return EOF if remoteClosed (remoteClosed + deadOnEmpty + dead)
	if s.b.Len() == 0 && (s.state == remoteClosed || s.state == dead) {
		return 0, io.EOF
	}

	if s.readDeadlineExceeded {
		return 0, ErrReadTimeout
	}

	if s.endErr != nil {
		return 0, s.endErr
	}

	n, _ := s.b.Read(buf)
	if err := s.session.send(newAckFrame(s.id, uint32(n))); err != nil {
		return n, err
	}

	s.session.logger.Printf("stream %d: read completed", s.id)

	return n, nil
}

// Write writes bytes to the stream
func (s *stream) Write(buf []byte) (int, error) {

	s.m.Lock()
	defer s.m.Unlock()
	defer s.c.Broadcast()

	l, w := len(buf), 0
	for w < l {

		for s.unblocked == 0 && s.endErr == nil && !s.writeDeadlineExceeded && s.state != closed && s.state != dead {
			s.session.logger.Printf("stream %d: write waiting", s.id)
			// wait for signal
			s.c.Wait()
		}

		// if stream is closed or waiting to be empty then abort
		// unblocked not checked as stream can be closed, but bytes may be unblocked by remote
		if s.state == closed || s.state == dead {
			return w, ErrBrokenPipe
		}

		if s.writeDeadlineExceeded {
			return w, ErrWriteTimeout
		}

		if s.endErr != nil {
			return w, s.endErr
		}

		cap := min(len(buf), int(s.unblocked))
		if err := s.session.send(newDataFrame(s.id, buf[:cap])); err != nil {
			return w, err
		}
		buf = buf[cap:]
		s.unblocked -= uint32(cap)
		w += cap
	}

	return w, nil
}
