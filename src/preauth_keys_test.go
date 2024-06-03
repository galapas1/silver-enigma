package ninjapanda

import (
	"time"

	"gopkg.in/check.v1"
)

func (*Suite) TestCreatePreAuthKey(c *check.C) {
	_, err := app.CreatePreAuthKey("bogus", "", 0, false, nil, nil)

	c.Assert(err, check.Equals, ErrNamespaceNotFound)

	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	key, err := app.CreatePreAuthKey(namespace.Name, "", 0, false, nil, nil)
	c.Assert(err, check.IsNil)

	// Did we get a valid key?
	c.Assert(key.Key, check.NotNil)
	c.Assert(len(key.Key), check.Equals, 48)

	// Make sure the Namespace association is populated
	c.Assert(key.Namespace.Name, check.Equals, namespace.Name)

	_, err = app.ListPreAuthKeys("bogus")
	c.Assert(err, check.NotNil)

	keys, err := app.ListPreAuthKeys(namespace.Name)
	c.Assert(err, check.IsNil)
	c.Assert(len(keys), check.Equals, 1)

	// Make sure the Namespace association is populated
	c.Assert((keys)[0].Namespace.Name, check.Equals, namespace.Name)
}

func (*Suite) TestExpiredPreAuthKey(c *check.C) {
	namespace, err := app.CreateNamespace("test2")
	c.Assert(err, check.IsNil)

	now := time.Now().UTC()
	pak, err := app.CreatePreAuthKey(
		namespace.Name,
		"",
		0,
		false,
		&now,
		nil,
	)
	c.Assert(err, check.IsNil)

	key, err := app.checkKeyValidityByKeyId(pak.PreAuthKeyId)
	c.Assert(err, check.Equals, ErrPreAuthKeyExpired)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestPreAuthKeyDoesNotExist(c *check.C) {
	key, err := app.checkKeyValidityByAuthKey("potatoKey")
	c.Assert(err, check.Equals, ErrPreAuthKeyNotFound)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestValidateKeyOk(c *check.C) {
	namespace, err := app.CreateNamespace("test3")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, "", 0, false, nil, nil)
	c.Assert(err, check.IsNil)

	key, err := app.checkKeyValidityByAuthKey(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestAlreadyUsedKey(c *check.C) {
	namespace, err := app.CreateNamespace("test4")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, "", 1, false, nil, nil)
	c.Assert(err, check.IsNil)

	machine := Machine{
		ID:             0,
		MachineId:      "foo",
		MachineKey:     "foo",
		NodeKey:        "bar",
		SessionKey:     "faa",
		Hostname:       "testest",
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	key, err := app.checkKeyValidityByKeyId(pak.PreAuthKeyId)
	c.Assert(err, check.Equals, ErrPreAuthKeyHasBeenDepleted)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestReusableBeingUsedKey(c *check.C) {
	namespace, err := app.CreateNamespace("test5")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, "", 0, false, nil, nil)
	c.Assert(err, check.IsNil)

	machine := Machine{
		ID:             1,
		MachineId:      "foo",
		MachineKey:     "foo",
		NodeKey:        "bar",
		SessionKey:     "faa",
		Hostname:       "testest",
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	key, err := app.checkKeyValidityByAuthKey(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestNotReusableNotBeingUsedKey(c *check.C) {
	namespace, err := app.CreateNamespace("test6")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, "", 1, false, nil, nil)
	c.Assert(err, check.IsNil)

	key, err := app.checkKeyValidityByAuthKey(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestEphemeralKey(c *check.C) {
	namespace, err := app.CreateNamespace("test7")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, "", 0, true, nil, nil)
	c.Assert(err, check.IsNil)

	now := time.Now().UTC()
	machine := Machine{
		ID:             0,
		MachineId:      "foo",
		MachineKey:     "foo",
		NodeKey:        "bar",
		SessionKey:     "faa",
		Hostname:       "testest",
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		LastSeen:       &now,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	_, err = app.checkKeyValidityByAuthKey(pak.Key)
	// Ephemeral keys are by definition reusable
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test7", "testest")
	c.Assert(err, check.IsNil)
	app.expireEphemeralWorker()

	// The machine record should have been deleted
	_, err = app.GetMachine("test7", "testest")
	c.Assert(err, check.NotNil)
}

func (*Suite) TestExpirePreauthKey(c *check.C) {
	namespace, err := app.CreateNamespace("test3")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, "", 0, false, nil, nil)
	c.Assert(err, check.IsNil)
	c.Assert(pak.Expiration, check.IsNil)

	pak, err = app.ExpirePreAuthKey(pak)
	c.Assert(err, check.IsNil)
	c.Assert(pak.Expiration, check.NotNil)

	key, err := app.checkKeyValidityByAuthKey(pak.Key)
	c.Assert(err, check.Equals, ErrPreAuthKeyExpired)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestNotReusableMarkedAsUsed(c *check.C) {
	namespace, err := app.CreateNamespace("test6")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, "", 1, false, nil, nil)
	c.Assert(err, check.IsNil)
	pak.UsedCount = 1
	app.db.Save(&pak)

	pak, err = app.checkKeyValidityByKeyId(pak.PreAuthKeyId)
	c.Assert(err, check.Equals, ErrPreAuthKeyHasBeenDepleted)
}

// TBD: PreAuthKeys wit ACL tags under consideration.
func (*Suite) tbdTestPreAuthKeyACLTags(c *check.C) {
	namespace, err := app.CreateNamespace("test8")
	c.Assert(err, check.IsNil)

	_, err = app.CreatePreAuthKey(
		namespace.Name,
		"",
		0,
		false,
		nil,
		[]string{"badtag"},
	)
	c.Assert(err, check.NotNil) // Confirm that malformed tags are rejected

	tags := []string{"tag:test1", "tag:test2"}
	tagsWithDuplicate := []string{"tag:test1", "tag:test2", "tag:test2"}
	_, err = app.CreatePreAuthKey(
		namespace.Name,
		"",
		0,
		false,
		nil,
		tagsWithDuplicate,
	)
	c.Assert(err, check.IsNil)

	listedPaks, err := app.ListPreAuthKeys("test8")
	c.Assert(err, check.IsNil)
	c.Assert(listedPaks[0].toProto(false).AclTags, check.DeepEquals, tags)
}
