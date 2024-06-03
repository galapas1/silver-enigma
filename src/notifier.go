package ninjapanda

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

type Notifier struct {
	np        *Ninjapanda
	l         sync.RWMutex
	machines  map[string]chan<- StateUpdate
	connected map[string]bool
}

func NewNotifier(app *Ninjapanda) *Notifier {
	return &Notifier{
		np:        app,
		machines:  make(map[string]chan<- StateUpdate),
		connected: make(map[string]bool),
	}
}

func NotifyCtx(ctxIn context.Context, origin, hostname string) context.Context {
	ctxOut, _ := context.WithTimeout(
		context.WithValue(
			context.WithValue(ctxIn, "hostname", hostname),
			"origin",
			origin,
		),
		3*time.Second,
	)
	return ctxOut
}

func (n *Notifier) AddMachine(machineKey string, c chan<- StateUpdate) {
	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey).
		Msg("acquiring lock to add machine")

	defer log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey).
		Msg("releasing lock to add machine")

	n.l.Lock()
	defer n.l.Unlock()

	if n.machines == nil {
		n.machines = make(map[string]chan<- StateUpdate)
	}

	n.machines[machineKey] = c
	n.connected[machineKey] = true

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey).
		Int(logtags.MakeTag("OpenChannels"), len(n.machines)).
		Msg("added new channel")

	totalConnectedClients.Set(float64(len(n.machines)))
}

func (n *Notifier) RemoveMachine(machineKey string) {
	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey).
		Msg("acquiring lock to remove machine")

	defer log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey).
		Msg("releasing lock to remove machine")

	n.l.Lock()
	defer n.l.Unlock()

	if n.machines == nil {
		return
	}

	delete(n.machines, machineKey)
	n.connected[machineKey] = false

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey).
		Int(logtags.MakeTag("OpenChannels"), len(n.machines)).
		Msg("removed channel")

	totalConnectedClients.Set(float64(len(n.machines)))
}

func (n *Notifier) IsConnected(machineKey string) bool {
	n.l.RLock()
	defer n.l.RUnlock()

	if _, ok := n.machines[machineKey]; ok {
		return true
	}

	return false
}

func (n *Notifier) ConnectedMap() map[string]bool {
	return n.connected
}

func (n *Notifier) NotifyAll(ctx context.Context, update StateUpdate) {
	n.NotifyWithIgnore(ctx, update)
}

func (n *Notifier) NotifyWithIgnore(
	ctx context.Context,
	update StateUpdate,
	ignore ...string,
) {
	log.Trace().
		Caller().
		Interface(logtags.GetTag(logtags.stateUpdate, "Type"), update.Type).
		Msg("acquiring lock to notify")

	defer log.Trace().
		Caller().
		Interface(logtags.GetTag(logtags.stateUpdate, "Type"), update.Type).
		Msg("releasing lock, finished notifying")

	n.l.RLock()
	defer n.l.RUnlock()

	for key := range n.machines {
		if IsStringInSlice(ignore, key) {
			log.Debug().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineKey"), key).
				Msg("ignoring for update")

			continue
		}

		n.notifyMachine(ctx, update, key)
	}
}

func (n *Notifier) NotifyByMachineKey(
	ctx context.Context,
	update StateUpdate,
	mKey string,
) {
	log.Trace().
		Caller().
		Interface(logtags.GetTag(logtags.stateUpdate, "Type"), update.Type).
		Msg("acquiring lock to notify")

	defer log.Trace().
		Caller().
		Interface(logtags.GetTag(logtags.stateUpdate, "Type"), update.Type).
		Msg("releasing lock, finished notifying")

	n.l.RLock()
	defer n.l.RUnlock()

	n.notifyMachine(ctx, update, mKey)
}

func (n *Notifier) notifyMachine(
	ctx context.Context,
	update StateUpdate,
	mKey string,
) {
	if c, ok := n.machines[mKey]; ok {
		select {
		case <-ctx.Done():
			log.Error().
				Caller().
				Err(ctx.Err()).
				Str(logtags.GetTag(logtags.machine, "MachineKey"), mKey).
				Any(logtags.MakeTag("Origin"), ctx.Value("origin")).
				Any(logtags.GetTag(logtags.machine, "Hostname"), ctx.Value("hostname")).
				Msg("update not sent, context cancelled")

			return
		case c <- update:
			machine, err := n.np.GetMachineByMachineKey(mKey)
			if err != nil {
				// inconceivable...
				log.Error().
					Caller().
					Err(err).
					Str(logtags.GetTag(logtags.machine, "MachineKey"), mKey).
					Any(logtags.MakeTag("Origin"), ctx.Value("origin")).
					Msg("failed to find connected machine in database")

				return
			}
			log.Trace().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineKey"), mKey).
				Any(logtags.MakeTag("Origin"), ctx.Value("origin")).
				Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
				Msg("update successfully sent on chan")

			user, _ := n.np.GetUserProfileByMachineId(machine.MachineId, true)
			username := "---"
			if user != nil {
				username = user.LoginName
			}
			updateRequestsSentToMachine.WithLabelValues(username, machine.Hostname, "success").
				Inc()

			n.np.SendMachineUpdate(machine)

			if update.StartTime != nil {
				duration := time.Since(*update.StartTime).Seconds()
				clientUpdateLatency.With(
					prometheus.Labels{
						"update_type": update.Message,
					},
				).Observe(duration)
			}
		}
	} else {
		log.Info().
			Caller().
			Str(logtags.GetTag(logtags.machine, "MachineKey"), mKey).
			Any(logtags.MakeTag("Origin"), ctx.Value("origin")).
			Any(logtags.GetTag(logtags.machine, "Hostname"), ctx.Value("hostname")).
			Msg("not connected to this ninja-panda")

		n.QueueNotification(ctx, mKey, update)
	}
}

func (n *Notifier) QueueNotification(
	ctx context.Context,
	machineKey string,
	update StateUpdate,
) {
	origin, ok := ctx.Value("origin").(string)
	if ok && origin == "notify-from-queue" {
		return
	}

	// TODO: queue a meaningful StateUpdate
	// for now... we'll just 'blast' update all
	//
	// If this doesn't queue, it just means the machine
	// isn't online... if it comes on line, this ninjapanda
	// will see it and update as needed
	n.np.HAQueueUpdate(ctx, machineKey, update)
}

func (n *Notifier) NotifyFromQueue() {
	ctx := NotifyCtx(context.Background(), "notify-from-queue", "na")
	n.NotifyAll(ctx,
		StateUpdate{
			Type: StateFullUpdate,
		})
}

func (n *Notifier) String() string {
	n.l.RLock()
	defer n.l.RUnlock()

	str := []string{"Notifier, in map:\n"}

	for k, v := range n.machines {
		str = append(str, fmt.Sprintf("\t%s: %v\n", k, v))
	}

	return strings.Join(str, "")
}
